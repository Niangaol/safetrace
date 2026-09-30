/**
 * E-07 · 连续运行（72h 证据）统计：从调度器运行日志算可用率与连续时长。
 *
 * 口径（写死在代码里，交件报告与看板引用同一份，避免文档和实现漂移）：
 * - 心跳节拍 = 所有 active 源里最小的 poll_interval_s（当前 1800s），期望心跳数 = floor(窗口/节拍)+1；
 * - 覆盖率 = 窗口内出现过的不同 run_at 数 / 期望心跳数；一次心跳里只要有任一源失败（ok=false）仍算「有运行」，
 *   但会计入 failed_runs，报告里两个数一起给，不把「跑过」说成「全成功」；
 * - 连续时长：相邻 run_at 间隔 ≤ 1.5×节拍 视为同一段，段时长 = 末次 − 首次 + 节拍（补上最后一次心跳的覆盖面）；
 * - 降级不是失败：degraded_to=fixture 表示外网不可达时按红线显式回放样本，计入 degraded_runs 单独披露。
 */
import { readFile } from "node:fs/promises";
import type { RunRecord } from "./scheduler.js";

export interface UptimeSegment {
  started_at: string;
  finished_at: string;
  duration_ms: number;
  heartbeats: number;
}

export interface UptimeStats {
  window_start: string;
  window_end: string;
  /** 心跳节拍（秒），取自 active 源最小 poll_interval_s。 */
  heartbeat_s: number;
  /** 节拍来源：explicit=调用方指定；inferred=由日志最小间隔推断；insufficient=心跳太少推断不出可信节拍。 */
  heartbeat_source: "explicit" | "inferred" | "insufficient";
  heartbeats_expected: number;
  heartbeats_observed: number;
  /** 观测到的覆盖率（0~1），上限截到 1。 */
  coverage_ratio: number;
  /**
   * 覆盖率是否可信。心跳 < 3 次、或推断出的节拍粗于 1 小时，说明这是"手动跑了两轮"
   * 而不是"常驻挂机"，此时 100% 是假信号，必须显式标注不可信（红线 5：不许演）。
   */
  coverage_reliable: boolean;
  reliability_note: string;
  runs_total: number;
  failed_runs: number;
  degraded_runs: number;
  /** 按源聚合的失败次数（用于回答「哪个源在拖后腿」）。 */
  failures_by_source: Record<string, number>;
  degraded_by_source: Record<string, number>;
  longest_continuous_ms: number;
  total_uptime_ms: number;
  segments: UptimeSegment[];
}

/** 读运行日志（JSONL，每行一个 RunRecord）；坏行跳过并计数，不让整张看板因为一行脏数据黑掉。 */
export async function readRunLog(file: string): Promise<{ records: RunRecord[]; bad_lines: number }> {
  let text = "";
  try {
    text = await readFile(file, "utf8");
  } catch {
    return { records: [], bad_lines: 0 };
  }
  const records: RunRecord[] = [];
  let bad_lines = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      const parsed = JSON.parse(trimmed) as RunRecord;
      if (typeof parsed.run_at === "string" && typeof parsed.source_id === "string") records.push(parsed);
      else bad_lines += 1;
    } catch {
      bad_lines += 1;
    }
  }
  return { records, bad_lines };
}

export interface UptimeOpts {
  /** 统计窗口，缺省为日志覆盖的全部时间。 */
  windowStart?: string;
  windowEnd?: string;
  /** 心跳节拍（秒）；显式给出则不再推断。 */
  heartbeat_s?: number;
  /** 兜底节拍（秒）：应为 active 源里最小的 poll_interval_s（当前 1800）。日志太稀时用它的期望数。 */
  defaultHeartbeatS?: number;
}

function toMs(iso: string): number | null {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/**
 * 解析心跳节拍。
 * 关键防呆：日志只有两三次稀疏手动运行时间隔很大时，**不能**把那个大间隔当成"节拍"——
 * 否则期望心跳数=观测数，覆盖率永远算出 100% 的假信号。间隔大于 4×兜底节拍即判为推断失败。
 */
function resolveHeartbeat(
  timesInWindow: readonly number[],
  opts: UptimeOpts,
): { ms: number; source: "explicit" | "inferred" | "insufficient" } {
  const fallbackS = opts.defaultHeartbeatS ?? 1800;
  if (opts.heartbeat_s !== undefined) return { ms: opts.heartbeat_s * 1000, source: "explicit" };
  const sorted = [...new Set(timesInWindow)].sort((a, b) => a - b);
  let min = Number.POSITIVE_INFINITY;
  for (let i = 1; i < sorted.length; i += 1) {
    const d = sorted[i]! - sorted[i - 1]!;
    if (d > 0) min = Math.min(min, d);
  }
  if (!Number.isFinite(min) || min > fallbackS * 1000 * 4) {
    return { ms: fallbackS * 1000, source: "insufficient" };
  }
  return { ms: Math.max(60_000, min), source: "inferred" };
}

export function computeUptime(records: readonly RunRecord[], opts: UptimeOpts = {}): UptimeStats {
  const times = records
    .map((r) => toMs(r.run_at))
    .filter((t): t is number => t !== null);
  const startFilter = opts.windowStart !== undefined ? toMs(opts.windowStart) : null;
  const endFilter = opts.windowEnd !== undefined ? toMs(opts.windowEnd) : null;
  const inWindow = records.filter((r) => {
    const t = toMs(r.run_at);
    if (t === null) return false;
    if (startFilter !== null && t < startFilter) return false;
    if (endFilter !== null && t > endFilter) return false;
    return true;
  });

  const inWindowTimes = inWindow
    .map((r) => toMs(r.run_at))
    .filter((t): t is number => t !== null);
  const heartbeat = resolveHeartbeat(inWindowTimes, opts);
  const heartbeatMs = heartbeat.ms;
  const observedTimes = [...new Set(inWindow.map((r) => r.run_at))]
    .map((s) => toMs(s) ?? Number.NaN)
    .filter((t) => !Number.isNaN(t))
    .sort((a, b) => a - b);

  const windowStartMs = startFilter ?? observedTimes[0] ?? Date.now();
  const windowEndMs = endFilter ?? observedTimes[observedTimes.length - 1] ?? Date.now();
  const spanMs = Math.max(0, windowEndMs - windowStartMs);
  const expected = Math.floor(spanMs / heartbeatMs) + 1;
  const observed = observedTimes.length;

  const failures: Record<string, number> = {};
  const degraded: Record<string, number> = {};
  for (const r of inWindow) {
    if (!r.ok) failures[r.source_id] = (failures[r.source_id] ?? 0) + 1;
    if (r.degraded_to !== undefined) degraded[r.source_id] = (degraded[r.source_id] ?? 0) + 1;
  }

  // —— 连续段合并 ——
  const segments: UptimeSegment[] = [];
  let cur: number[] = [];
  const pushSegment = (): void => {
    if (cur.length === 0) return;
    const first = cur[0]!;
    const last = cur[cur.length - 1]!;
    segments.push({
      started_at: new Date(first).toISOString(),
      finished_at: new Date(last).toISOString(),
      duration_ms: last - first + heartbeatMs,
      heartbeats: cur.length,
    });
    cur = [];
  };
  for (const t of observedTimes) {
    if (cur.length === 0 || t - cur[cur.length - 1]! <= heartbeatMs * 1.5) cur.push(t);
    else {
      pushSegment();
      cur.push(t);
    }
  }
  pushSegment();

  const longest = segments.reduce((acc, s) => Math.max(acc, s.duration_ms), 0);
  const total = segments.reduce((acc, s) => acc + s.duration_ms, 0);
  const coverageReliable = heartbeat.source !== "insufficient" && observed >= 3;
  const reliabilityNote =
    heartbeat.source === "insufficient"
      ? "心跳太稀疏（最小间隔大于 4×兜底节拍）⇒ 这是手动跑几轮，不是常驻挂机；覆盖率按兜底节拍 " +
        Math.round(heartbeatMs / 1000) + "s 计期望，数字仅供参考，不可作为 72h 证据"
      : observed < 3
        ? "心跳不足 3 次，覆盖率无统计意义；先常驻运行 npm run ingest:watch 再取数"
        : "心跳节拍由日志推断且样本≥3，覆盖率可作为运行证据";

  return {
    window_start: new Date(windowStartMs).toISOString(),
    window_end: new Date(windowEndMs).toISOString(),
    heartbeat_s: Math.round(heartbeatMs / 1000),
    heartbeat_source: heartbeat.source,
    heartbeats_expected: expected,
    heartbeats_observed: observed,
    coverage_ratio: Math.min(1, Math.round((observed / Math.max(1, expected)) * 10000) / 10000),
    coverage_reliable: coverageReliable,
    reliability_note: reliabilityNote,
    runs_total: inWindow.length,
    failed_runs: inWindow.filter((r) => !r.ok).length,
    degraded_runs: inWindow.filter((r) => r.degraded_to !== undefined).length,
    failures_by_source: failures,
    degraded_by_source: degraded,
    longest_continuous_ms: longest,
    total_uptime_ms: total,
    segments,
  };
}
