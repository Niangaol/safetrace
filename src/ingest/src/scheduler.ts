/**
 * E-07 · Y 线周期调度器（时效看板与 72h 挂机证据的载体）。
 *
 * 台账原文：「registry.ts 的 poll_interval_s 只是字段声明，runIngestOnce() 是单次函数」——
 * 本模块把它变成真的调度：按每个源自己登记的 poll_interval_s 到点抓取，
 * 并把每轮结果写进本地运行日志（默认 tmp/ingest-runs.jsonl，不进总线、不动 contracts/events.md 的主题清单）。
 *
 * 可测性：时钟与休眠都可注入（nowMs / sleep），单测不需要真等 30 分钟。
 * 优雅退出：shouldStop() 返回 true 时立即结束循环；SIGINT 由调用侧接（本模块不注册进程信号）。
 */
import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { SqliteEventStore } from "@safetrace/shared";
import type { EventStore } from "@safetrace/shared";
import { activeSources } from "./registry.js";
import { REPO_ROOT, readJsonFile, isOfflineEnv } from "./common.js";
import { MemorySourceScheduleStore, SqliteSourceScheduleStore } from "./schedule-state.js";
import type { SourceScheduleStore, SourceRunStatus, SourceScheduleState } from "./schedule-state.js";
import type { IngestRunResult, RunIngestOnceOpts } from "./pipeline.js";
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
  status?: SourceRunStatus;
  finished_at?: string;
  coverage_complete?: boolean;
  /** source=某源的抓取结果；tick=进程存活心跳（本轮没有任何源到点也会写，可用率据此算）。 */
  kind?: "source" | "tick";
}

export interface SchedulerOpts {
  /** 事件存储；缺省用 SQLITE_PATH / var/safetrace.sqlite。注入 store 时应显式提供持久 scheduleState。 */
  store?: EventStore;
  scheduleState?: SourceScheduleStore;
  /** Separate SQLite metadata DB. Defaults to event DB path + .schedule.sqlite for owned stores. */
  scheduleStatePath?: string;
  maxConcurrency?: number;
  /** Keep recent records in memory; the complete history remains in JSONL. */
  maxRetainedRecords?: number;
  runSource?: (sourceId: string, opts: RunIngestOnceOpts) => Promise<IngestRunResult>;
  runIngest?: (opts: RunIngestOnceOpts) => Promise<IngestRunResult>;
  onIngestResult?: (sourceId: string, result: IngestRunResult, finishedAt: string) => void | Promise<void>;
  /** Extra delay after failures, never shorter than the official poll interval. */
  failureBackoffMs?: (failures: number, sourceId: string) => number;
  overlapMs?: number;
  /** Operator-selected freshness profile. Registry defaults remain unchanged; ≥300s, transport rate limits still apply. */
  pollIntervalOverridesS?: Readonly<Record<string, number>>;
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
  records_total?: number;
  records_dropped_from_memory?: number;
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
/** Classify coverage independently from pipeline/DQ admission success. */
export async function classifyIngestRun(result: IngestRunResult, offline = false): Promise<SourceRunStatus> {
  if (offline || result.degraded_to === "fixture" || result.fallbackEvents.some(e => e.degraded_of === "fixture") || result.fetched.some(r => r.external_id.endsWith("_fixture"))) return "fixture";
  if (result.fallbackEvents.some(e => e.degraded_of === "partial")) return "partial";
  for (const raw of result.fetched) {
    const payload = await readJsonFile(raw.payload_ref) as Record<string, unknown>;
    if (payload.partial === true) return "partial";
    if (payload.truncated === true) return "truncated";
  }
  if (result.fetched.length === 0 || result.parsed.length === 0) return "no_data";
  return "complete";
}

/** NVD explicitly proves all requested dual windows completed, including official no-results. */
async function completeEmptyNvdCoverage(result: IngestRunResult): Promise<boolean> {
  if (result.fetched.length !== 1 || result.fetched[0]?.source_id !== "nvd_cve") return false;
  const payload = await readJsonFile(result.fetched[0].payload_ref) as Record<string, unknown>;
  if (payload.coverage_complete !== true || payload.partial === true || payload.truncated === true || !Array.isArray(payload.windows) || !Array.isArray(payload.vulnerabilities) || payload.vulnerabilities.length !== 0) return false;
  const windows = payload.windows as Array<Record<string, unknown>>;
  return windows.some(w => w.kind === "pubDate") && windows.some(w => w.kind === "lastMod") && windows.every(w => w.failed_pages === 0 && w.truncated === false);
}

/** Independent live source jobs: a slow source cannot hold the scheduling clock.
 * ONE monitoring leader per live namespace is required. The durable get/set state is NOT
 * a distributed lease; simultaneous scheduler instances must be fenced by their caller.
 * Offline runs use a separate offline:source namespace and never suppress live scheduling.
 */
export async function runIngestScheduler(opts: SchedulerOpts = {}): Promise<SchedulerSummary> {
  const nowMs = opts.nowMs ?? Date.now;
  const sleep = opts.sleep ?? defaultSleep;
  const checkIntervalMs = opts.checkIntervalMs ?? 30_000;
  const concurrency = opts.maxConcurrency ?? 2;
  const retain=opts.maxRetainedRecords??1000;
  if(!Number.isSafeInteger(retain)||retain<1)throw new Error("maxRetainedRecords must be positive integer");
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) throw new Error("maxConcurrency must be a positive integer");
  if (!Number.isFinite(checkIntervalMs) || checkIntervalMs <= 0) throw new Error("checkIntervalMs must be positive");
  const offline = opts.offline === true || isOfflineEnv();
  const stateKey = (id: string): string => offline ? "offline:" + id : id;
  const overlapMs = opts.overlapMs ?? 3600_000;
  if (!Number.isFinite(overlapMs) || overlapMs < 0) throw new Error("overlapMs must be nonnegative");
  const runLogPath = opts.runLogPath === undefined ? defaultRunLogPath() : opts.runLogPath;
  let store = opts.store;
  if (!store) {
    await mkdir(path.dirname(defaultDbPath()), { recursive: true });
    store = new SqliteEventStore(defaultDbPath());
  }
  let ownedState: SqliteSourceScheduleStore | undefined;
  let scheduleState = opts.scheduleState;
  if (!scheduleState) {
    const filename = opts.scheduleStatePath ?? (opts.store === undefined ? defaultDbPath() + ".schedule.sqlite" : undefined);
    if (filename) {
      await mkdir(path.dirname(filename), { recursive: true });
      ownedState = new SqliteSourceScheduleStore(filename);
      scheduleState = ownedState;
    } else scheduleState = new MemorySourceScheduleStore();
  }
  const entries = activeSources().filter(s => opts.sourceIds === undefined || opts.sourceIds.includes(s.source_id)).map(source => {
    const seconds=opts.pollIntervalOverridesS?.[source.source_id];
    if(seconds===undefined)return source;
    if(!Number.isSafeInteger(seconds)||seconds<300)throw new Error("poll interval override must be at least 300 seconds");
    return {...source,poll_interval_s:seconds};
  });
  if (!entries.length) { ownedState?.close(); throw new Error("调度器无可调度源：registry 里没有 active 源"); }
  const states = new Map<string, SourceScheduleState>();
  for (const e of entries) {
    const state = await scheduleState.get(stateKey(e.source_id));
    if (state) states.set(e.source_id, state);
  }
  const cveSeedState = await loadCveSeeds(store);
  const records: RunRecord[] = [];let recordsTotal=0;
  const startedAt = new Date(nowMs()).toISOString();
  let cycles = 0;
  const pending: string[] = [];
  const reserved = new Set<string>();
  const running = new Set<Promise<void>>();
  let fatal: unknown;
  const execute = async (sourceId: string): Promise<void> => {
    const atMs = nowMs();
    const previous = states.get(sourceId);
    const entry = entries.find(e => e.source_id === sourceId)!;
    let status: SourceRunStatus = "failed";
    let coverageComplete = false;
    let error: string | undefined;
    let result: IngestRunResult | undefined;
    let finishedAt: string;
    // Reserve the poll interval durably before network IO: a crash/restart cannot hammer the source.
    await scheduleState.set({ source_id: stateKey(sourceId), last_attempt_at: new Date(atMs).toISOString(), last_success_at: previous?.last_success_at ?? null, next_due_at: new Date(atMs + entry.poll_interval_s * 1000).toISOString(), consecutive_failures: previous?.consecutive_failures ?? 0, status: "failed" });
    try {
      const cve_ids = sourceId === "osv" || sourceId === "cve_org" ? nextCveSeeds(cveSeedState, sourceId) : undefined;
      const end = new Date(atMs).toISOString();
      const cursor = previous?.last_success_at;
      const sourceOptions = sourceId === "nvd_cve" ? { nvd_cve: {
        window: { start: cursor ? new Date(Date.parse(cursor) - overlapMs).toISOString() : new Date(atMs - 24 * 3600_000).toISOString(), end },
        pubWindow: { start: cursor ? new Date(Date.parse(cursor) - overlapMs).toISOString() : new Date(atMs - 48 * 3600_000).toISOString(), end },
      } } : undefined;
      const runOpts: RunIngestOnceOpts = { store, offline: opts.offline, sourceIds: [sourceId], ...(opts.limit !== undefined ? { limit: opts.limit } : {}), ...(cve_ids?.length ? { cve_ids } : {}), ...(sourceOptions ? { sourceOptions } : {}) };
      result = await (opts.runSource ? opts.runSource(sourceId, runOpts) : (opts.runIngest ?? runIngestOnce)(runOpts));
      finishedAt = new Date(nowMs()).toISOString();
      // Handoff is awaited BEFORE advancing coverage: a failed durable enqueue must stay retryable.
      await opts.onIngestResult?.(sourceId, result, finishedAt);
      status = await classifyIngestRun(result, offline);
      coverageComplete = status === "complete" || (!offline && status === "no_data" && await completeEmptyNvdCoverage(result));
      rememberCveItems(cveSeedState, result.parsed);
      if (cve_ids?.length && status === "complete") {
        const seen = sourceId === "osv" ? cveSeedState.osvSeen : cveSeedState.cveOrgSeen;
        for (const id of cve_ids) seen.add(id);
      }
    } catch (err) { status = "failed"; coverageComplete = false; error = err instanceof Error ? err.message : String(err); }
    finishedAt = new Date(nowMs()).toISOString();
    const failures = status === "failed" || status === "partial" || status === "truncated" ? (previous?.consecutive_failures ?? 0) + 1 : 0;
    const backoff = failures ? (opts.failureBackoffMs?.(failures, sourceId) ?? Math.min(24 * 3600_000, 60_000 * 2 ** Math.min(failures - 1, 20))) : 0;
    if (!Number.isFinite(backoff) || backoff < 0) throw new Error("failureBackoffMs must return a finite nonnegative delay");
    const state: SourceScheduleState = {
      source_id: stateKey(sourceId), last_attempt_at: new Date(atMs).toISOString(),
      last_success_at: coverageComplete ? new Date(atMs).toISOString() : previous?.last_success_at ?? null,
      next_due_at: new Date(nowMs() + Math.max(entry.poll_interval_s * 1000, backoff)).toISOString(),
      consecutive_failures: failures, status,
    };
    await scheduleState.set(state);
    states.set(sourceId, state);
    const record: RunRecord = { run_at: new Date(atMs).toISOString(), finished_at: finishedAt, source_id: sourceId, ok: status !== "failed", status, coverage_complete: coverageComplete,
      fetched: result?.fetched.length ?? 0, parsed: result?.parsed.length ?? 0, merged: result?.merged.length ?? 0,
      verdicts: result?.verdicts.length ?? 0, fallback_events: result?.fallbackEvents.length ?? 0,
      ...(result?.degraded_to ? { degraded_to: result.degraded_to } : {}), ...(error ? { error } : {}) };
    recordsTotal++;records.push(record);if(records.length>retain)records.shift();
    opts.onRecord?.(record);
    await appendRunLog(runLogPath, record);
  };
  const dispatch = (): void => {
    if(opts.shouldStop?.()){for(const id of pending)reserved.delete(id);pending.length=0;return;}
    while (pending.length && running.size < concurrency && !fatal) {
      const id = pending.shift()!;
      const job = execute(id).catch(err => { fatal = err; }).finally(() => { running.delete(job); reserved.delete(id); dispatch(); });
      running.add(job);
    }
  };
  const drain = async (): Promise<void> => { while (running.size) await Promise.all([...running]); };
  try {
    for (;;) {
      if (opts.shouldStop?.() || fatal) break;
      const at = nowMs();
      for (const e of entries) {
        if (!reserved.has(e.source_id) && (!states.has(e.source_id) || Date.parse(states.get(e.source_id)!.next_due_at) <= at)) {
          reserved.add(e.source_id); pending.push(e.source_id);
        }
      }
      dispatch();
      // Offline replay is deterministic and deliberately has no live freshness claim.
      if (offline) await drain();
      await appendRunLog(runLogPath, { run_at: new Date(at).toISOString(), source_id: "_heartbeat", ok: true, fetched: 0, parsed: 0, merged: 0, verdicts: 0, fallback_events: 0, kind: "tick" });
      cycles += 1;
      if (opts.maxCycles && cycles >= opts.maxCycles) break;
      await sleep(checkIntervalMs);
    }
    await drain();
    if (fatal) throw fatal;
    return { cycles, records, records_total:recordsTotal,records_dropped_from_memory:recordsTotal-records.length, started_at: startedAt, finished_at: new Date(nowMs()).toISOString() };
  } finally {
    await drain();
    ownedState?.close();
    if (opts.store === undefined) store.close();
  }
}
