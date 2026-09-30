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
import { runIngestScheduler, defaultDbPath, type RunRecord } from "../scheduler.js";
import { activeSourceIds } from "../registry.js";

const args = process.argv.slice(2);
const has = (flag: string): boolean => args.includes(flag);
const valueOf = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

let stopping = false;

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
  const summary = await runIngestScheduler({
    store,
    offline: has("--offline"),
    ...(sourceIds !== undefined ? { sourceIds } : {}),
    ...(has("--once") ? { maxCycles: 1 } : {}),
    ...(Number.isFinite(cycleMs) && cycleMs > 0 ? { checkIntervalMs: cycleMs } : {}),
    shouldStop: () => stopping,
    onRecord: log,
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
