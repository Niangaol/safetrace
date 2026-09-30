/**
 * Y4/时效看板（E-02）：监测延迟 lag = first_seen_at − published_at 的口径与统计。
 *
 * 为什么单独建模块：台账砍⑤ 早就写了「保留 freshness.ts 的实时数」，但仓库里此前并没有这个文件；
 * 而 P-08 要求每个指标必须先定义「样本规模 / 时间窗 / 统计方法」，否则数字不可辩护。本模块写死四条口径：
 *
 *  1. 样本集：只取 `published_at` 落在统计窗口内（缺省最近 7 天）且非离线回放的情报行。
 *  2. 去重：一条情报只算一个样本（按 intel_id 去重，取最早 first_seen_at）；跨轮重复上报计入 duplicate_intel_rows。
 *  3. 统计方法：P50/P95 用最近秩法（nearest-rank，向上取整）；≤6h 占比 = lag ≤ 21600s 的样本比例。
 *     上游时间戳只到秒，所以分位数保留 1 位小数，再细的精度是假的。
 *  4. 双口径（关键）：
 *     - `overall`  严格口径：只计 `published_at ≥ 监控起点` 的条目 ⇒「我们开始监测之后新发布的漏洞，多久被抓到」，
 *       这才是「监测时效」，也是决赛 ≤6h 优秀档的对应证据；
 *     - `reference` 参考口径：窗口内全部真实条目（含上线前发布、本次才首次见到的历史 CVE）⇒
 *       lag 里混进了上游自身的发布/更新延迟（实测 NVD 按 lastMod 增量返回的条目 published 可能是两天前），
 *       只能当背景分布看，不能写进「监测延迟」结论。
 *     两个口径同时出，避免「上线第一天严格口径 n=0、看板空白」被误读成「系统没在跑」。
 *
 * 红线（禁静默兜底 + Mock 要说出口）：凡 raw_refs 全部指向 fixtures/ 的行一律不参与统计，
 * 并单独输出 excluded.fixture_rows——离线回放样本的 published_at 是历史样本时间，拿它算 lag 不是监测时效。
 */
import { lagSeconds, parseLoose } from "@safetrace/shared";
import type { EventStore, IntelItem, RawDoc, FallbackEvent } from "@safetrace/shared";

/** 指标口径版本：口径变更必须升版本，避免不同版本数字混在同一张表里。 */
export const FRESHNESS_METRIC_VERSION = "1.1.0";

/** 决赛「时效 ≤6h 优秀档」阈值（秒）。 */
export const SLA_6H_SECONDS = 6 * 3600;

/** 已知源标识（fallback.events 的 payload 上没有 source_id，只能按文本回指）。 */
const KNOWN_SOURCE_IDS = ["cisa_kev", "nvd_cve", "osv", "cve_org", "ubuntu_usn", "ghsa", "arxiv"] as const;

/** 最近秩法分位数（输入必须已升序）；空集返回 null（不许造 0）。 */
export function percentile(sortedSeconds: readonly number[], q: number): number | null {
  if (sortedSeconds.length === 0) return null;
  const rank = Math.ceil(q * sortedSeconds.length);
  const idx = Math.min(sortedSeconds.length - 1, Math.max(0, rank - 1));
  return sortedSeconds[idx] ?? null;
}

export interface LatencyStats {
  /** 参与统计的样本数。 */
  n: number;
  p50_seconds: number | null;
  p95_seconds: number | null;
  max_seconds: number | null;
  /** lag ≤ 6h 的样本占比（0~1）；无样本为 null。 */
  sla_6h_ratio: number | null;
}

export interface SourceLatencyRow extends LatencyStats {
  source_id: string;
}

export interface FreshnessWindow {
  start: string;
  end: string;
}

export interface WatermarkRow {
  source: string;
  last_sync_at: string | null;
  last_full_sync_at: string | null;
  last_published_at: string | null;
  items_last_run: number;
  success: boolean;
  /** 不可用/降级的原因（显式披露，红线 3）。 */
  error: string | null;
  /** true 表示本轮该源处于离线回放态（raw.docs 的 payload_ref 指向 fixtures/）。 */
  replaying_fixture: boolean;
  /** true 表示本轮没有产出 raw.doc（例如 OSV 需要查询目标、cve.org 需要 CVE 游标）。 */
  skipped_this_run: boolean;
}

export interface FreshnessStatsBlock {
  overall: LatencyStats;
  by_source: SourceLatencyRow[];
}

export interface FreshnessReport {
  generated_at: string;
  metric_version: string;
  lag_definition: string;
  percentile_method: string;
  window: FreshnessWindow;
  /**
   * 监控起点（调度器最早一轮抓取时间）。
   * null = 还没有运行日志，此时严格口径退化为参考口径（并在 sample_basis 里说明）。
   */
  monitor_start: string | null;
  sample_basis: string;
  /** live=严格口径有样本；backfill_only=窗口内只有上线前发布的条目；fixture_only=一条真实样本都没有。 */
  data_basis: "live" | "backfill_only" | "fixture_only";
  /** 严格口径：published_at ≥ 监控起点。 */
  overall: LatencyStats;
  by_source: SourceLatencyRow[];
  /** 参考口径：窗口内全部真实条目（含上线前发布的历史 CVE）。 */
  reference: FreshnessStatsBlock & { note: string };
  /** 分源统计的归并口径说明。 */
  by_source_note: string;
  excluded: {
    /** raw_refs 全部指向 fixtures/ 的行数（离线回放样本）。 */
    fixture_rows: number;
    /** published_at 不在窗口内。 */
    out_of_window: number;
    /** 上线前发布、本次才首次见到的条目（计入参考口径，不计入严格口径）。 */
    published_before_monitor_start: number;
    /** 时间戳不可解析。 */
    unparseable: number;
    /** lag < 0（first_seen 早于 published，多为上游补录或时钟偏差）。 */
    negative_lag: number;
    /** 按 intel_id 去重折叠掉的重复上报行数。 */
    duplicate_intel_rows: number;
  };
  collect: {
    sources_registered: number;
    sources_active: number;
    /** 原始条目数 = 运行日志里各轮 parsed 之和；无日志为 0。 */
    raw_items: number;
    /** 去重后的真实（非 fixture）情报条数。 */
    intel_items: number;
    /** 归并率 = 1 − intel_items / raw_items。 */
    merge_ratio: number;
    merge_ratio_note: string;
  };
  watermarks: WatermarkRow[];
  /** 未消费队列深度：本实现为同步投递，恒为 0；字段保留以对齐前端契约。 */
  queue_depth: number;
  fallback_total: number;
}

export interface ComputeFreshnessOpts {
  /** 统计窗口，缺省 [now-7d, now]。 */
  window?: FreshnessWindow;
  /** 基准时间（测试注入）。 */
  now?: Date;
  /** 登记源总数与 active 源数（由调用方从 registry 传入，避免本模块依赖 registry）。 */
  sources?: { registered: number; active: number };
  /** 监控起点（调度器首轮时间）；null/缺省 ⇒ 严格口径退化为参考口径。 */
  monitorStart?: string | null;
  /** 运行日志汇总：各轮解析条目数之和（归并率的分母）。 */
  runTotals?: { parsed: number };
  /**
   * active 源 id 列表（registry 传入）。水位以它为全集：
   * 本轮没产 raw.doc 的源也要占一行，否则「5 个在跑源只亮 3 盏灯」会被读成系统在跑而实际漏了 2 个。
   */
  activeSourceIds?: string[];
}

interface Sample {
  intel_id: string;
  source_ids: string[];
  published_ms: number;
  first_seen_ms: number;
  lag_seconds: number;
}

/** raw_refs 全部指向 fixtures/ ⇒ 该行来自离线回放样本。 */
function isFixtureRow(item: IntelItem): boolean {
  const refs = Array.isArray(item.raw_refs) ? item.raw_refs : [];
  if (refs.length === 0) return false;
  return refs.every((r) => typeof r === "string" && r.startsWith("fixtures/"));
}

function statsOf(lags: number[]): LatencyStats {
  const sorted = [...lags].sort((a, b) => a - b);
  const sla = sorted.length === 0 ? null : sorted.filter((s) => s <= SLA_6H_SECONDS).length / sorted.length;
  return {
    n: sorted.length,
    p50_seconds: percentile(sorted, 0.5),
    p95_seconds: percentile(sorted, 0.95),
    max_seconds: sorted.length === 0 ? null : sorted[sorted.length - 1] ?? null,
    sla_6h_ratio: sla,
  };
}

/** 秒数保留 1 位小数；比例保留 4 位。 */
function round1(x: number | null): number | null {
  return x === null ? null : Math.round(x * 10) / 10;
}

function withRounded(s: LatencyStats): LatencyStats {
  return {
    ...s,
    p50_seconds: round1(s.p50_seconds),
    p95_seconds: round1(s.p95_seconds),
    max_seconds: round1(s.max_seconds),
    sla_6h_ratio: s.sla_6h_ratio === null ? null : Math.round(s.sla_6h_ratio * 10000) / 10000,
  };
}

function blockOf(samples: readonly Sample[]): FreshnessStatsBlock {
  const bySource = new Map<string, number[]>();
  for (const s of samples) {
    for (const sid of s.source_ids) {
      const list = bySource.get(sid) ?? [];
      list.push(s.lag_seconds);
      bySource.set(sid, list);
    }
  }
  return {
    overall: withRounded(statsOf(samples.map((s) => s.lag_seconds))),
    by_source: [...bySource.entries()]
      .map(([source_id, lags]) => ({ source_id, ...withRounded(statsOf(lags)) }))
      .sort((a, b) => b.n - a.n || a.source_id.localeCompare(b.source_id)),
  };
}

/** FallbackEvent 上没有 source_id 字段，源信息只出现在 trigger/label 文本里，这里按已知源标识回指。 */
function sourceOfFallback(e: FallbackEvent): string {
  const text = JSON.stringify(e);
  for (const key of KNOWN_SOURCE_IDS) {
    if (text.includes(key)) return key;
  }
  return "global";
}

/**
 * 从事件存储计算时效报告。
 * 只读三个主题：intel.items（延迟样本）、raw.docs（水位与条数）、fallback.events（降级计数）。
 */
export async function computeFreshnessReport(store: EventStore, opts: ComputeFreshnessOpts = {}): Promise<FreshnessReport> {
  const now = opts.now ?? new Date();
  const endIso = now.toISOString();
  const startIso = opts.window?.start ?? new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString();
  const endMs = parseLoose(opts.window?.end ?? endIso) ?? now.getTime();
  const startMs = parseLoose(startIso) ?? now.getTime() - 7 * 24 * 3600 * 1000;
  const monitorStartMs = opts.monitorStart != null ? parseLoose(opts.monitorStart) : null;

  const intelEnvs = await store.read<IntelItem>("intel.items", 0, 100_000);
  const rawEnvs = await store.read<RawDoc>("raw.docs", 0, 100_000);
  const fallbackEnvs = await store.read<FallbackEvent>("fallback.events", 0, 100_000);

  const excluded = {
    fixture_rows: 0,
    out_of_window: 0,
    published_before_monitor_start: 0,
    unparseable: 0,
    negative_lag: 0,
    duplicate_intel_rows: 0,
  };
  /** intel_id → 最早一次入库的那条。 */
  const bestByIntel = new Map<string, Sample>();

  for (const env of intelEnvs) {
    const item = env.payload;
    if (isFixtureRow(item)) {
      excluded.fixture_rows += 1;
      continue;
    }
    const pubMs = parseLoose(item.published_at ?? "");
    const seenMs = parseLoose(item.first_seen_at ?? "");
    if (pubMs === null || seenMs === null) {
      excluded.unparseable += 1;
      continue;
    }
    if (pubMs < startMs || pubMs > endMs) {
      excluded.out_of_window += 1;
      continue;
    }
    const lag = lagSeconds(item.published_at, item.first_seen_at);
    if (lag === null) {
      excluded.unparseable += 1;
      continue;
    }
    if (lag < 0) {
      excluded.negative_lag += 1;
      continue;
    }
    const sample: Sample = {
      intel_id: item.intel_id,
      source_ids: item.source_ids,
      published_ms: pubMs,
      first_seen_ms: seenMs,
      lag_seconds: lag,
    };
    const prev = bestByIntel.get(item.intel_id);
    if (prev !== undefined) {
      excluded.duplicate_intel_rows += 1;
      if (seenMs < prev.first_seen_ms) bestByIntel.set(item.intel_id, sample);
      continue;
    }
    bestByIntel.set(item.intel_id, sample);
  }

  const referenceSamples = [...bestByIntel.values()];
  const strictSamples =
    monitorStartMs === null
      ? referenceSamples
      : referenceSamples.filter((s) => s.published_ms >= monitorStartMs);
  excluded.published_before_monitor_start = referenceSamples.length - strictSamples.length;

  const strictBlock = blockOf(strictSamples);
  const referenceBlock = blockOf(referenceSamples);
  const distinctIntelIds = new Set<string>();
  for (const env of intelEnvs) {
    if (!isFixtureRow(env.payload)) distinctIntelIds.add(env.payload.intel_id);
  }
  const intelDistinct = distinctIntelIds.size;
  const parsedRows = opts.runTotals?.parsed ?? 0;
  const mergeRatio = parsedRows > 0 ? Math.min(1, Math.max(0, 1 - intelDistinct / parsedRows)) : 0;

  // —— 水位：全集 = active 源（registry 传入）。本轮没产 raw.doc 的源也必须占一行，
  //    否则「5 个在跑源只亮 3 盏灯」会被读成系统在跑，而实际是另外 2 个没发起请求。 ——
  const lastFallbackBySource = new Map<string, string>();
  for (const env of fallbackEnvs) {
    const e = env.payload;
    lastFallbackBySource.set(sourceOfFallback(e), String(e.degraded_of ?? e.degraded_state?.label ?? "degrade"));
  }

  interface DocAgg { last: string; first: string; replaying: boolean }
  const perSourceDocs = new Map<string, DocAgg>();
  for (const env of rawEnvs) {
    const doc = env.payload;
    const at = doc.fetched_at || env.occurred_at;
    const isReplay = doc.payload_ref.startsWith("fixtures/") || doc.external_id.endsWith("_fixture");
    const cur = perSourceDocs.get(doc.source_id);
    if (cur === undefined) perSourceDocs.set(doc.source_id, { last: at, first: at, replaying: isReplay });
    else {
      if (Date.parse(at) >= Date.parse(cur.last)) {
        cur.last = at;
        cur.replaying = isReplay;
      }
      if (Date.parse(at) <= Date.parse(cur.first)) cur.first = at;
    }
  }

  const universe = opts.activeSourceIds ?? [...perSourceDocs.keys()];
  const watermarks: WatermarkRow[] = [...universe]
    .sort((a, b) => a.localeCompare(b))
    .map((sourceId) => {
      const agg = perSourceDocs.get(sourceId);
      const inWindowForSource = referenceSamples.filter((s) => s.source_ids.includes(sourceId));
      const latestPublished = inWindowForSource.map((s) => s.published_ms).sort((a, b) => b - a)[0];
      if (agg === undefined) {
        return {
          source: sourceId,
          last_sync_at: null,
          last_full_sync_at: null,
          last_published_at: null,
          items_last_run: 0,
          success: false,
          error: "本轮未产出 raw.doc（该源需要查询目标或增量游标才发起抓取）",
          replaying_fixture: false,
          skipped_this_run: true,
        };
      }
      const degrade = lastFallbackBySource.get(sourceId);
      return {
        source: sourceId,
        last_sync_at: agg.last,
        last_full_sync_at: agg.first,
        last_published_at: latestPublished !== undefined ? new Date(latestPublished).toISOString() : null,
        items_last_run: inWindowForSource.length,
        success: !agg.replaying,
        error: agg.replaying ? "fixture（离线回放预置样本" + (degrade !== undefined ? "：" + degrade : "") + "）" : null,
        replaying_fixture: agg.replaying,
        skipped_this_run: false,
      };
    });

  const dataBasis: FreshnessReport["data_basis"] =
    strictSamples.length > 0 ? "live" : referenceSamples.length > 0 ? "backfill_only" : "fixture_only";

  return {
    generated_at: endIso,
    metric_version: FRESHNESS_METRIC_VERSION,
    lag_definition: "lag = first_seen_at − published_at（秒），按 intel_id 去重取最早 first_seen_at",
    percentile_method: "nearest-rank（向上取整），空集返回 null",
    window: { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() },
    monitor_start: opts.monitorStart ?? null,
    sample_basis:
      monitorStartMs === null
        ? "无运行日志 ⇒ 严格口径暂等同参考口径；跑起 npm run ingest:watch 后自动收窄"
        : "严格口径只计 published_at ≥ 监控起点的条目；参考口径计窗口内全部真实条目",
    data_basis: dataBasis,
    overall: strictBlock.overall,
    by_source: strictBlock.by_source,
    reference: {
      ...referenceBlock,
      note: "含上线前发布、本次才首次见到的历史条目：lag 里混入上游发布/更新延迟，不可写成「监测延迟」",
    },
    by_source_note: "一条多源归并的情报同时计入它每个来源的样本，因此各源 n 之和可能大于 overall.n（这是归并口径，不是重复计数错误）",
    excluded,
    collect: {
      sources_registered: opts.sources?.registered ?? 0,
      sources_active: opts.sources?.active ?? 0,
      raw_items: parsedRows,
      intel_items: intelDistinct,
      merge_ratio: Math.round(mergeRatio * 10000) / 10000,
      merge_ratio_note: "归并率 = 1 − 去重后情报条数 / 运行日志累计解析条目数；无运行日志时为 0（不用抓取批次数冒充分母）",
    },
    watermarks,
    queue_depth: 0,
    fallback_total: fallbackEnvs.length,
  };
}

/** 打表用（台账砍⑤ 的「三口径数字打表」也走这里，可直接截图进 PPT）。 */
export function formatFreshnessTable(report: FreshnessReport): string {
  const h = (s: number | null): string => (s === null ? "—" : s >= 3600 ? `${(s / 3600).toFixed(2)}h` : `${s.toFixed(0)}s`);
  const pct = (x: number | null): string => (x === null ? "—" : `${(x * 100).toFixed(1)}%`);
  const line = (label: string, st: LatencyStats): string =>
    `${label} n=${String(st.n).padStart(4)} P50=${h(st.p50_seconds).padStart(8)} P95=${h(st.p95_seconds).padStart(9)} max=${h(st.max_seconds).padStart(9)} ≤6h占比=${pct(st.sla_6h_ratio)}`;
  const lines: string[] = [];
  lines.push(`时效报告 metric_version=${report.metric_version} data_basis=${report.data_basis}`);
  lines.push(`窗口 ${report.window.start} ~ ${report.window.end}` + (report.monitor_start !== null ? `｜监控起点 ${report.monitor_start}` : ""));
  lines.push(line("【严格】监测延迟（上线后发布）", report.overall));
  lines.push(line("【参考】窗口全量分布（含回填）", report.reference.overall));
  if (report.by_source.length > 0) {
    lines.push("严格口径分源：");
    for (const r of report.by_source) {
      lines.push(`  ${r.source_id.padEnd(12)} n=${String(r.n).padStart(4)} P50=${h(r.p50_seconds).padStart(8)} P95=${h(r.p95_seconds).padStart(9)} ≤6h=${pct(r.sla_6h_ratio).padStart(7)}`);
    }
  }
  lines.push(
    `排除：fixture=${report.excluded.fixture_rows} 窗口外=${report.excluded.out_of_window} 上线前发布=${report.excluded.published_before_monitor_start} ` +
      `不可解析=${report.excluded.unparseable} 负lag=${report.excluded.negative_lag} 重复=${report.excluded.duplicate_intel_rows}`,
  );
  lines.push(
    `采集：登记 ${report.collect.sources_registered} 源 / 在跑 ${report.collect.sources_active} 源｜累计解析 ${report.collect.raw_items} 条 ` +
      `→ 去重 ${report.collect.intel_items} 条（归并率 ${(report.collect.merge_ratio * 100).toFixed(2)}%）｜降级事件 ${report.fallback_total}`,
  );
  lines.push("水位（active 源全集，成功=真联网抓到）：");
  for (const w of report.watermarks) {
    const state = w.skipped_this_run ? "未抓取" : w.replaying_fixture ? "回放中" : "正常";
    lines.push(
      `  ${w.source.padEnd(12)} ${state.padEnd(6)} last_sync=${w.last_sync_at ?? "—"} 窗口内条目=${String(w.items_last_run).padStart(4)}` +
        (w.error !== null ? ` ｜${w.error}` : ""),
    );
  }
  return lines.join("\n");
}
