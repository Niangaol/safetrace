/**
 * E-07 · 采集守护进程：按 registry 的 poll_interval_s 周期抓取并落 SQLite。
 * 用法：
 *   node --import tsx src/ingest/src/cli/watch.ts                     # 真联网，常驻（72h 证据的来源）
 *   node --import tsx src/ingest/src/cli/watch.ts -- --offline        # 只回放 fixtures（演示/CI）
 *   node --import tsx src/ingest/src/cli/watch.ts -- --once           # 每源跑一轮就退出
 *   node --import tsx src/ingest/src/cli/watch.ts -- --source osv,ubuntu_usn   # 只调度指定源
 *   node --import tsx src/ingest/src/cli/watch.ts -- --cycle-ms 60000 # 覆盖检查间隔（调试用）
 *   node --import tsx src/ingest/src/cli/watch.ts -- --cycle-ms 60000 # 覆盖检查间隔（调试用）
 * Ctrl-C 优雅退出：等当前轮结束再关库。
 */
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { SqliteEventStore } from "@safetrace/shared";
import { AssetsStore, autoMatchIntel, defaultAssetsDbPath } from "@safetrace/assets";
import { runIngestScheduler, defaultDbPath, type RunRecord } from "../scheduler.js";
import { activeSourceIds } from "../registry.js";

const args = process.argv.slice(2);
const has = (flag: string): boolean => args.includes(flag);
const valueOf = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

let stopping = false;

/** 资产自动匹配节流：同一组件同一 CVE 的告警在存储层去重，这里只控匹配频率。 */
const AUTO_MATCH_INTERVAL_MS = 15 * 60_000;
let lastAutoMatchAt = 0;

/**
 * 新情报入库后与最新资产快照做确定性匹配，命中即落告警。
 * 纪律：失败只记日志不打断采集（显式失败）；无快照时明说"先跑一次扫描"。
 */
async function autoMatch(eventStore: SqliteEventStore, force: boolean): Promise<void> {
  const now = Date.now();
  if (!force && now - lastAutoMatchAt < AUTO_MATCH_INTERVAL_MS) return;
  lastAutoMatchAt = now;
  const assets = new AssetsStore(defaultAssetsDbPath());
  try {
    const report = await autoMatchIntel(eventStore, assets);
    if (report.skipped_reason !== null) {
      console.log("[assets] 自动匹配跳过：" + report.skipped_reason);
      return;
    }
    console.log(
      "[assets] 自动匹配：情报=" + report.items_read + " 组件=" + report.components +
        " 命中=" + report.affected + " 新增提醒=" + report.new_alerts,
    );
  } catch (error) {
    console.log("[assets] 自动匹配失败（不打断采集）：" + (error instanceof Error ? error.message : String(error)));
  } finally {
    assets.close();
  }
}

function log(record: RunRecord): void {
  const bits = [
    record.run_at,
    record.source_id.padEnd(12),
    record.ok ? "OK " : "FAIL",
    `fetched=${record.fetched}`,
    `parsed=${record.parsed}`,
    `merged=${record.merged}`,
    `dq=${record.verdicts}`,
    `fallback=${record.fallback_events}`,
  ];
  if (record.degraded_to !== undefined) bits.push(`degraded_to=${record.degraded_to}`);
  if (record.error !== undefined) bits.push(`error=${record.error}`);
  console.log("[ingest] " + bits.join(" "));
}

async function main(): Promise<number> {
  const dbPath = defaultDbPath();
  await mkdir(path.dirname(dbPath), { recursive: true }); // node:sqlite 不建父目录
  const store = new SqliteEventStore(dbPath);
  console.log("[ingest] 事件库=" + dbPath);
  console.log("[ingest] 调度源=" + activeSourceIds().join(",") + (has("--offline") ? " (离线回放 fixtures)" : " (真联网)"));
  console.log("[ingest] 轮询节奏来自 registry.poll_interval_s；Ctrl-C 优雅退出");

  const onSigint = (): void => {
    if (stopping) return;
    stopping = true;
    console.log("\n[ingest] 收到退出信号，等当前轮结束后关闭事件库…");
  };
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigint);

  const cycleMs = Number(valueOf("--cycle-ms") ?? 60_000);
  const sourceArg = valueOf("--source") ?? args.find((a) => a.startsWith("--source="))?.slice("--source=".length);
  const sourceIds = sourceArg !== undefined && sourceArg !== "" ? sourceArg.split(",").map((s) => s.trim()).filter((s) => s !== "") : undefined;
  if (sourceIds !== undefined) console.log("[ingest] 限定源=" + sourceIds.join(","));
  // 启动即匹配一次（幂等）：让"常驻模式"下的历史情报也能对照最新快照产出提醒
  await autoMatch(store, true);

  const summary = await runIngestScheduler({
    store,
    offline: has("--offline"),
    ...(sourceIds !== undefined ? { sourceIds } : {}),
    ...(has("--once") ? { maxCycles: 1 } : {}),
    ...(Number.isFinite(cycleMs) && cycleMs > 0 ? { checkIntervalMs: cycleMs } : {}),
    shouldStop: () => stopping,
    onRecord: async (record) => {
      log(record);
      if (record.merged > 0) await autoMatch(store, false);
    },
  });

  const ok = summary.records.filter((r) => r.ok).length;
  const degraded = summary.records.filter((r) => r.degraded_to !== undefined).length;
  console.log(
    `[ingest] 结束：轮次=${summary.cycles} 记录=${summary.records.length} 成功=${ok} 失败=${summary.records.length - ok} 显式降级=${degraded}`,
  );
  store.close();
  // 单源失败已在运行记录里逐条留痕（含 error 字段），不作为进程失败——否则 72h 挂机会被一次 429 打断
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("[ingest] 异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });
