/**
 * E-02 · 时效看板取数 CLI：从事件库算 lag 分布 + 从运行日志算连续运行，
 * 一次性输出 JSON（给前端）与表格（打表/截图）。
 *
 * 用法：
 *   node --import tsx src/ingest/src/cli/report.ts                       # 窗口=最近 7 天，写 tmp/freshness.json
 *   node --import tsx src/ingest/src/cli/report.ts -- --days 3
 *   node --import tsx src/ingest/src/cli/report.ts -- --out docs/evidence/freshness.json
 *
 * 为什么不用 ops/scripts/uptime.sh：本仓在 Windows 上 npm 走 cmd.exe，bash 钩子正是 R-01
 * 修掉的那类假绿源头，所以可用率与时效数字统一由这一个跨平台 Node 入口出（两条验收命令合成一条）。
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { SqliteEventStore, parseLoose } from "@safetrace/shared";
import { SOURCES, activeSources } from "../registry.js";
import { computeFreshnessReport, formatFreshnessTable } from "../freshness.js";
import { computeUptime, readRunLog, type UptimeStats } from "../uptime.js";
import { defaultDbPath, defaultRunLogPath } from "../scheduler.js";

const args = process.argv.slice(2);
const valueOf = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

const DAY_MS = 24 * 3600 * 1000;

function hours(ms: number): string {
  return `${(ms / 3600_000).toFixed(2)}h`;
}

function formatUptime(stats: UptimeStats): string {
  return [
    `连续运行（E-07）窗口 ${stats.window_start} ~ ${stats.window_end}`,
    `节拍=${stats.heartbeat_s}s（${stats.heartbeat_source}）心跳 期望=${stats.heartbeats_expected} 观测=${stats.heartbeats_observed} 覆盖率=${(stats.coverage_ratio * 100).toFixed(2)}%${stats.coverage_reliable ? "" : "（不可信，见下）"}`,
    `最长连续=${hours(stats.longest_continuous_ms)} 累计在线=${hours(stats.total_uptime_ms)} 段数=${stats.segments.length} 失败轮=${stats.failed_runs} 显式降级轮=${stats.degraded_runs}`,
    ...stats.segments.slice(-6).map((s) => `  段 ${s.started_at} → ${s.finished_at}（${hours(s.duration_ms)}，${s.heartbeats} 次心跳）`),
    `  可信度：${stats.reliability_note}`,
    ...(Object.keys(stats.failures_by_source).length > 0 ? ["  失败分布：" + JSON.stringify(stats.failures_by_source)] : []),
    ...(Object.keys(stats.degraded_by_source).length > 0 ? ["  降级分布：" + JSON.stringify(stats.degraded_by_source)] : []),
  ].join("\n");
}

async function main(): Promise<number> {
  const dbPath = defaultDbPath();
  const logPath = defaultRunLogPath();
  await mkdir(path.dirname(dbPath), { recursive: true }); // node:sqlite 不会自己建父目录

  const rawDays = Number(valueOf("--days") ?? "7");
  const days = Number.isFinite(rawDays) && rawDays > 0 ? rawDays : 7;
  const now = new Date();
  const window = { start: new Date(now.getTime() - days * DAY_MS).toISOString(), end: now.toISOString() };

  // —— 先读运行日志：监控起点与归并率分母都来自它，必须早于时效计算 ——
  const { records, bad_lines } = await readRunLog(logPath);
  const sinceArg = valueOf("--since"); // 取证窗口起点（ISO-8601）；用于分段挂机时锁定本轮 72h
  const sinceMs = sinceArg !== undefined ? parseLoose(sinceArg) : null;
  if (sinceArg !== undefined && sinceMs === null) {
    console.error("--since 不是合法时间（需要 ISO-8601，例如 2026-10-01T00:00:00Z）");
    return 1;
  }
  const sourceRecords = records.filter((r) => r.kind !== "tick" && (sinceMs === null || Date.parse(r.run_at) >= sinceMs));
  const monitorStart = sourceRecords.length > 0 ? [...sourceRecords].sort((a, b) => a.run_at.localeCompare(b.run_at))[0]!.run_at : null;
  const parsedTotal = sourceRecords.reduce((acc, r) => acc + (Number.isFinite(r.parsed) ? r.parsed : 0), 0);

  const store = new SqliteEventStore(dbPath);
  let report;
  try {
    report = await computeFreshnessReport(store, {
      window,
      sources: { registered: SOURCES.length, active: activeSources().length },
      activeSourceIds: activeSources().map((s) => s.source_id),
      monitorStart,
      runTotals: { parsed: parsedTotal },
    });
  } finally {
    store.close();
  }

  // 连续运行的窗口从监控起点算起（不是报告窗口）：
  // 否则刚上线时「7 天窗口里只有 1 轮」会被算成 0.3% 覆盖率，读起来像系统挂了。
  const minPollS = activeSources().reduce((acc, s) => Math.min(acc, s.poll_interval_s), Number.POSITIVE_INFINITY);
  const uptime = records.length > 0
    ? computeUptime(records, {
        ...(monitorStart !== null ? { windowStart: monitorStart } : {}),
        defaultHeartbeatS: Number.isFinite(minPollS) ? minPollS : 1800,
      })
    : null;

  const out = valueOf("--out") ?? path.join("tmp", "freshness.json");
  const outDir = path.dirname(out);
  await mkdir(outDir === "" ? "." : outDir, { recursive: true });
  await writeFile(
    out,
    JSON.stringify(
      { ...report, uptime, run_log: { path: logPath, records: records.length, bad_lines }, event_db: dbPath },
      null,
      2,
    ),
    "utf8",
  );

  console.log(formatFreshnessTable(report));
  console.log("");
  console.log(uptime === null ? `[uptime] 运行日志为空（${logPath}）：先跑 node --import tsx src/ingest/src/cli/watch.ts 攒连续运行证据` : formatUptime(uptime));
  console.log("\n已写出：" + out);
  if (report.data_basis === "fixture_only") {
    console.log("注意：窗口内没有一条真实抓取样本，以上时效数字不可作为运行证据（红线 5：Mock 要说出口）。");
  }
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("[freshness] 异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });
