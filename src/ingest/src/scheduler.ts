/**
 * E-07 · Y 线周期调度器（时效看板与 72h 挂机证据的载体）。
 *
 * 台账原文：「registry.ts 的 poll_interval_s 只是字段声明，runIngestOnce() 是单次函数」——
 * 本模块把它变成真的调度：按每个源自己登记的 poll_interval_s 到点抓取，
 * 并把每轮结果写进本地运行日志（默认 tmp/ingest-runs.jsonl，不进总线、不动 contracts/events.md 的主题清单）。
 *
 * 可测性：时钟与休眠都可注入（nowMs / sleep），单测不需要真等 30 分钟。
 * 优雅退出：shouldStop() 返回 true 时立即结束循环；SIGINT 由调用侧（scripts/ingest-daemon.ts）接。
 */
import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { SqliteEventStore, nowIso } from "@safetrace/shared";
import type { EventStore } from "@safetrace/shared";
import { activeSources } from "./registry.js";
import { REPO_ROOT } from "./common.js";
import { runIngestOnce } from "./pipeline.js";

/** 每轮到点执行一次后写入日志的结构（口径：一次「源 × 轮次」= 一行）。 */
export interface RunRecord {
  run_at: string;
  source_id: string;
  ok: boolean;
  fetched: number;
  parsed: number;
  merged: number;
  verdicts: number;
  fallback_events: number;
  degraded_to?: string;
  error?: string;
  /** source=某源的抓取结果；tick=进程存活心跳（本轮没有任何源到点也会写，可用率据此算）。 */
  kind?: "source" | "tick";
}

export interface SchedulerOpts {
  /** 事件存储；缺省用 SQLITE_PATH / tmp/safetrace-ingest.sqlite 的 SQLite 实现（看板要读历史）。 */
  store?: EventStore;
  /** 只调度这些源（缺省为 registry 里全部 active 源）。 */
  sourceIds?: string[];
  /** 强制离线回放 fixtures（演示/自测）。 */
  offline?: boolean;
  /** 每源单轮公告条数上限（USN 用）。 */
  limit?: number;
  /** 轮询检查到点的间隔（毫秒），缺省 30s。 */
  checkIntervalMs?: number;
  /** 跑满 N 轮后退出（0/缺省 = 无限）。测试与一次性验证用。 */
  maxCycles?: number;
  nowMs?: () => number;
  sleep?: (ms: number) => Promise<void>;
  shouldStop?: () => boolean;
  onRecord?: (record: RunRecord) => void;
  /** 运行日志文件；null 表示不落盘（测试用）。 */
  runLogPath?: string | null;
}

export interface SchedulerSummary {
  cycles: number;
  records: RunRecord[];
  started_at: string;
  finished_at: string;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** 运行日志默认路径：tmp/ 已在 .gitignore，运行产物不进仓库。 */
export function defaultRunLogPath(): string {
  const fromEnv = process.env.SAFETRACE_RUN_LOG?.trim();
  return fromEnv !== undefined && fromEnv !== "" ? fromEnv : path.join(REPO_ROOT, "tmp", "ingest-runs.jsonl");
}

/**
 * 事件库默认路径：与上游既有 CLI（scripts/ingest-once.ts、crawl-page.ts、demo-page-ingest.ts）同一约定
 * `SQLITE_PATH ?? ./var/safetrace.sqlite` —— 否则本调度器攒的 72h 数据与队长的全链路留痕会落在两个库里，
 * `trace:lineage` / `vector:verify` 都读不到我这份数据。
 */
export function defaultDbPath(): string {
  const fromEnv = process.env.SQLITE_PATH?.trim();
  return fromEnv !== undefined && fromEnv !== "" ? path.resolve(fromEnv) : path.resolve(REPO_ROOT, "var", "safetrace.sqlite");
}

async function appendRunLog(file: string | null, record: RunRecord): Promise<void> {
  if (file === null || file === "") return;
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, JSON.stringify(record) + "\n", "utf8");
}

type CveSeedState = { byId: Map<string, string>; osvSeen: Set<string>; cveOrgSeen: Set<string> };

async function loadCveSeeds(store: EventStore): Promise<CveSeedState> {
  const state: CveSeedState = { byId: new Map(), osvSeen: new Set(), cveOrgSeen: new Set() };
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<{ cve_ids?: string[]; published_at?: string | null; source_ids?: string[] }>("intel.items", offset, 500);
    for (const event of page) rememberCveItems(state, [event.payload]);
    if (page.length < 500) return state;
  }
}

function rememberCveItems(state: CveSeedState, items: Array<{ cve_ids?: string[]; published_at?: string | null; source_ids?: string[] }>): void {
  for (const item of items) {
    for (const id of item.cve_ids ?? []) {
      const publishedAt = item.published_at ?? "";
      const previous = state.byId.get(id);
      if (previous === undefined || publishedAt > previous) state.byId.set(id, publishedAt);
    }
  }
}

function nextCveSeeds(state: CveSeedState, sourceId: string): string[] {
  const seen = sourceId === "osv" ? state.osvSeen : state.cveOrgSeen;
  const limit = sourceId === "cve_org" ? 1 : 10;
  return [...state.byId.entries()].filter(([id]) => !seen.has(id)).sort((a, b) => b[1].localeCompare(a[1])).slice(0, limit).map(([id]) => id);
}
/**
 * 主循环：每轮检查哪些源到点（lastRun + poll_interval_s <= now），到点的源逐个抓取。
 * 单源失败隔离：一个源抛错只记 ok=false，不影响其他源与后续轮次。
 */
export async function runIngestScheduler(opts: SchedulerOpts = {}): Promise<SchedulerSummary> {
  const nowMs = opts.nowMs ?? (() => Date.now());
  const sleep = opts.sleep ?? defaultSleep;
  const checkIntervalMs = opts.checkIntervalMs ?? 30_000;
  const runLogPath = opts.runLogPath === undefined ? defaultRunLogPath() : opts.runLogPath;
  let store = opts.store;
  if (store === undefined) {
    const dbPath = defaultDbPath();
    // node:sqlite 不会自己建目录；先确保父目录存在（tmp/ 已被 .gitignore 忽略）
    await mkdir(path.dirname(dbPath), { recursive: true });
    store = new SqliteEventStore(dbPath);
  }

  const entries = activeSources().filter((s) => (opts.sourceIds === undefined ? true : opts.sourceIds.includes(s.source_id)));
  if (entries.length === 0) throw new Error("调度器无可调度源：registry 里没有 active 源");

  /** source_id → 上次执行完成的毫秒时间戳（null = 从未跑过 ⇒ 启动即执行一轮）。 */
  const lastRunAt = new Map<string, number | null>(entries.map((e) => [e.source_id, null]));
  // 单源 scheduler 每个 runner 独立调用 pipeline；启动时从持久 intel.items 取 CVE 种子，避免 OSV/cve.org 永远空跑。
  const cveSeedState = await loadCveSeeds(store);
  const records: RunRecord[] = [];
  const startedAt = nowIso();
  let cycles = 0;

  const runSource = async (sourceId: string, atMs: number): Promise<void> => {
    let record: RunRecord;
    try {
      const cve_ids = sourceId === "osv" || sourceId === "cve_org" ? nextCveSeeds(cveSeedState, sourceId) : undefined;
      const res = await runIngestOnce({ store, offline: opts.offline, sourceIds: [sourceId], ...(opts.limit !== undefined ? { limit: opts.limit } : {}), ...(cve_ids?.length ? { cve_ids } : {}) });
      rememberCveItems(cveSeedState, res.parsed);
      if (cve_ids?.length) {
        const hasFixtureFallback = res.fallbackEvents.some((event) => event.degraded_of === "fixture");
        const hasPartialFailure = res.fallbackEvents.some((event) => event.degraded_of === "partial");
        const sourceItems = res.parsed.filter((item) => item.source_ids.includes(sourceId));
        const seen = sourceId === "osv" ? cveSeedState.osvSeen : cveSeedState.cveOrgSeen;
        if (!hasFixtureFallback) {
          const attempted = hasPartialFailure ? sourceItems.flatMap((item) => item.cve_ids) : cve_ids;
          for (const id of attempted) seen.add(id); // 404/no match is attempted; fixture failure stays retryable
        }
      }
      record = {
        run_at: new Date(atMs).toISOString(),
        source_id: sourceId,
        ok: true,
        fetched: res.fetched.length,
        parsed: res.parsed.length,
        merged: res.merged.length,
        verdicts: res.verdicts.length,
        fallback_events: res.fallbackEvents.length,
        ...(res.degraded_to !== undefined ? { degraded_to: res.degraded_to } : {}),
      };
    } catch (err) {
      record = {
        run_at: new Date(atMs).toISOString(),
        source_id: sourceId,
        ok: false,
        fetched: 0,
        parsed: 0,
        merged: 0,
        verdicts: 0,
        fallback_events: 0,
        error: err instanceof Error ? err.message : String(err),
      };
    }
    lastRunAt.set(sourceId, atMs);
    records.push(record);
    opts.onRecord?.(record);
    await appendRunLog(runLogPath, record);
  };

  for (;;) {
    if (opts.shouldStop?.() === true) break;
    const at = nowMs();
    const due = entries.filter((e) => {
      const last = lastRunAt.get(e.source_id) ?? null;
      return last === null || last + e.poll_interval_s * 1000 <= at;
    });
    for (const e of due) await runSource(e.source_id, at);
    // 进程存活心跳：每轮写一行（本轮没有源到点也写），可用率/连续时长以它为准，
    // 与「源抓取成功率」分开——两者混谈就是把「我还活着」说成「我Works」。
    const tick: RunRecord = {
      run_at: new Date(at).toISOString(),
      source_id: "_heartbeat",
      ok: true,
      fetched: 0,
      parsed: 0,
      merged: 0,
      verdicts: 0,
      fallback_events: 0,
      kind: "tick",
    };
    await appendRunLog(runLogPath, tick);
    cycles += 1;
    if (opts.maxCycles !== undefined && opts.maxCycles > 0 && cycles >= opts.maxCycles) break;
    await sleep(checkIntervalMs);
  }

  return { cycles, records, started_at: startedAt, finished_at: nowIso() };
}
