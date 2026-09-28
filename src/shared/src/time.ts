/**
 * 时间口径：全系统 ISO-8601 UTC 带 Z（契约硬规则：first_seen_at 与 published_at 分离，
 * lag = first_seen_at − published_at）。杜绝本地时区污染。
 */

/** 当前 UTC 时间，ISO-8601 带 Z。 */
export function nowIso(): string {
  return new Date().toISOString();
}

/**
 * 解析时间为 epoch ms。容忍三类上游脏数据：无时区（按 UTC 记）、
 * 早于 1999、晚于当前 +5min —— 后两者由 DQ1 硬红线捕获（见 dq1.ts 规则复用）。
 */
export function parseLoose(iso: string): number | null {
  if (!iso || typeof iso !== "string") return null;
  const cleaned = iso.trim();
  // 无时区后缀：按 UTC 解析，并在调用侧由 parseWarnings 记录
  const withTz = /[zZ]|[+-]\d{2}:?\d{2}$/.test(cleaned) ? cleaned : cleaned + "Z";
  const t = Date.parse(withTz);
  return Number.isNaN(t) ? null : t;
}

/** lag = first_seen − published（秒）。无法解析返回 null。 */
export function lagSeconds(publishedAt: string, firstSeenAt: string): number | null {
  const p = parseLoose(publishedAt);
  const f = parseLoose(firstSeenAt);
  if (p === null || f === null) return null;
  return Math.round((f - p) / 1000);
}

/** 单调递增 ID（时间有序，去重键 event_id/decision_id 生成用）。 */
let counter = 0;
export function nextId(prefix: string): string {
  counter = (counter + 1) % 100000;
  const ts = Date.now().toString(36).padStart(9, "0");
  return `${prefix}_${ts}${counter.toString(36).padStart(3, "0")}`;
}
