/**
 * Y1 · NVD CVE API 2.0 采集器。
 *
 * 两条窗口，缺一不可（2026-10-01 真机实测后写下的结论）：
 *  1. `lastModStartDate/lastModEndDate`：抓"最近被修改"的条目（含 NVD 补分析）；
 *  2. `pubStartDate/pubEndDate`：抓"最近新发布"的条目 —— **时效指标只有靠这条才有样本**。
 *     只查 lastMod 时实测：24h 窗口 `totalResults=3805`、单页只回 2000 条，且这一页里
 *     `published` 落在最近 8 小时的有 **0 条** ⇒ `first_seen − published` 的严格口径永远空集，
 *     "≤6h 优秀档"这种验收根本测不出来（不是数字难看，是根本没有样本）。
 *
 * 翻页：NVD 单页上限 2000。现在按 `startIndex` 逐页取到 `totalResults` 或单窗口上限
 * （`MAX_PAGES_PER_WINDOW`）为止；触顶就在 payload 写 `truncated` + 原因，由适配器转成 parse_warning 进总线，
 * 不静默截断（宁缺勿猜的另一种形态：截断必须说出口）。
 *
 * 礼貌与限流：无 `NVD_API_KEY` 时沿用 5 req/30s 令牌桶（每一页都过桶）；有 key 同样遵守 50 req/30s。每次 HTTP 重试也计入速率。
 * 只使用 NVD 官方参数，不塞自定义 query（自定义参数可能被判 400，且会污染复现命令）。
 *
 * 降级红线：
 *  - 显式离线回放 ⇒ `degradeToFixture`，`external_id` 以 `_fixture` 结尾（时效看板据此剔除该行）；
 *  - 两窗口官方空结果 ⇒ live no_data + 完整覆盖证明；全部失败 ⇒ partial，不拿 fixture 假装成功；
 *  - 只有部分页/窗口失败 ⇒ 记 `degraded_of="partial"` 的 FallbackEvent，**保留已取到的真实数据**，
 *    绝不拿 fixtures 顶替缺口；
 *  - NVD 的 `404`（No results found）是"该窗口无结果"的官方语义 ⇒ 算空不算错，也不回放样本。
 */
import { degrade, nextId, nowIso } from "@safetrace/shared";
import type { FallbackEvent, RawDoc } from "@safetrace/shared";
import {
  degradeToFixture,
  fetchJsonWithRetry,
  isOfflineEnv,
  persistPayload,
  readJsonFile,
  requireSource,
  sleep,
  type FetchOpts,
} from "../common.js";

const SOURCE_ID = "nvd_cve";
const FIXTURE = "fixtures/sources/nvd.sample.json";
/** 无 key 限流：5 请求 / 30 秒（NVD 官方速率）。 */
const NO_KEY_CAPACITY = 5;
const NO_KEY_WINDOW_MS = 30_000;
/** NVD 单页上限。 */
const RESULTS_PER_PAGE = 2000;
/** 单窗口最多翻几页（10 页 = 2 万条）；触顶即标 truncated。 */
const MAX_PAGES_PER_WINDOW = 10;
/** lastMod 窗口长度（小时）。 */
const LASTMOD_LOOKBACK_H = 24;
/** pubDate 窗口长度（小时），可用 SAFETRACE_NVD_PUB_LOOKBACK_HOURS 覆盖。 */
const DEFAULT_PUB_LOOKBACK_H = 48;
/** Official NVD query range limit. Bound catch-up work and report any unqueried tail. */
const MAX_WINDOW_MS = 120 * 24 * 3600_000;
const MAX_SEGMENTS_PER_KIND = 16;

/** 进程内速率窗口：无 key 5/30s，有 key 50/30s；离线不触发。 */
const requestTimes: number[] = [];
const keyedRequestTimes: number[] = [];

async function acquireToken(apiKey: string): Promise<void> {
  const times = apiKey === "" ? requestTimes : keyedRequestTimes;
  const capacity = apiKey === "" ? NO_KEY_CAPACITY : 50;
  const now = Date.now();
  while (times.length > 0 && (times[0] ?? 0) <= now - NO_KEY_WINDOW_MS) times.shift();
  if (times.length >= capacity) {
    const oldest = times[0] ?? now;
    await sleep(Math.max(0, oldest + NO_KEY_WINDOW_MS - now));
    await acquireToken(apiKey);
    return;
  }
  times.push(now);
}

/** NVD 只接受秒级精度 + 时区的 ISO 串（带毫秒会被 400 拒绝）。 */
function nvdTs(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface FetchNvdOpts extends FetchOpts {
  /** lastMod 窗口；缺省最近 24 小时。 */
  window?: { start: string; end: string };
  /** pubDate 窗口；缺省最近 48 小时。 */
  pubWindow?: { start: string; end: string };
  /** 只做 lastMod（对照实验/排障用）；默认两窗口都跑。 */
  skipPubWindow?: boolean;
  /**
   * 只做 pubDate（历史回补用）：跳过 lastMod 窗口，避免把近期已入库的几千条重新抓一遍。
   * 默认 false；为 true 时 `window` 被忽略。历史回补必须显式传 pubWindow。
   */
  skipLastModWindow?: boolean;
}

type WindowKind = "lastMod" | "pubDate";

interface WindowResult {
  kind: WindowKind;
  start: string;
  end: string;
  items: unknown[];
  totalResults: number;
  pages: number;
  truncated: boolean;
  failedPages: number;
  empty: boolean;
}

function buildRawDoc(payload: Record<string, unknown>, fetchedAt: string, payloadRef: string, externalId: string): RawDoc {
  const entry = requireSource(SOURCE_ID);
  return {
    source_id: SOURCE_ID,
    source_type: entry.source_type,
    external_id: externalId,
    url: entry.url,
    fetched_at: fetchedAt,
    content_type: "json",
    payload_ref: payloadRef,
  };
}

/** 单个窗口的翻页抓取。失败页只记 partial 降级，不回放 fixture。 */
async function fetchWindow(
  baseUrl: string,
  apiKey: string,
  kind: WindowKind,
  startIso: string,
  endIso: string,
  traceId: string,
  emit?: (event: FallbackEvent) => void | Promise<void>,
): Promise<WindowResult> {
  const items: unknown[] = [];
  let totalResults = 0;
  let pages = 0;
  let failedPages = 0;
  let truncated = false;
  let empty = false;

  const startKey = kind === "lastMod" ? "lastModStartDate" : "pubStartDate";
  const endKey = kind === "lastMod" ? "lastModEndDate" : "pubEndDate";
  const start = nvdTs(startIso);
  const end = nvdTs(endIso);
  const duration = Date.parse(end) - Date.parse(start);
  if (!Number.isFinite(duration) || duration <= 0 || duration > MAX_WINDOW_MS) throw new Error("Invalid NVD query window (must be >0 and <=120 days)");

  for (let pageIndex = 0; pageIndex < MAX_PAGES_PER_WINDOW; pageIndex += 1) {
    const startIndex = pageIndex * RESULTS_PER_PAGE;
    const url =
      baseUrl +
      "?" + startKey + "=" + encodeURIComponent(start) +
      "&" + endKey + "=" + encodeURIComponent(end) +
      "&resultsPerPage=" + RESULTS_PER_PAGE +
      "&startIndex=" + startIndex;
    // Every HTTP attempt, including retries, consumes an official rate token.
    let attempt: Awaited<ReturnType<typeof fetchJsonWithRetry>> = { ok: false, reason: "not attempted" };
    for (let retry = 0; retry < 3; retry++) {
      await acquireToken(apiKey);
      attempt = await fetchJsonWithRetry(url, { headers: apiKey === "" ? {} : { apiKey } }, 1);
      if (attempt.ok || /HTTP 4(?!29)/.test(attempt.reason)) break;
      if (retry < 2) await sleep(attempt.reason.includes("HTTP 429") ? NO_KEY_WINDOW_MS : 500 * 2 ** retry);
    }

    if (!attempt.ok) {
      if (attempt.reason.includes("HTTP 404")) {
        empty = items.length === 0; // A later empty page is not proof of complete coverage.
        if (items.length > 0 && items.length < totalResults) truncated = true;
        break;
      }
      failedPages += 1;
      await degrade({
        layer: "L1",
        trigger: `NVD ${kind} 第 ${startIndex} 条起抓取失败：${attempt.reason}`,
        degradedOf: "partial",
        traceId,
        label: `NVD ${kind} 窗口部分页失败（保留已取到的 ${items.length} 条，不用预置样本顶替缺口）`,
        recoveryHint: "下一轮窗口重叠会重新覆盖这段；缺失页不会变成假数据",
        emit,
      });
      break;
    }

    const data = attempt.data as Record<string, unknown> | null;
    if (!data || !Array.isArray(data.vulnerabilities) || !Number.isSafeInteger(data.totalResults) || Number(data.totalResults) < 0) {
      failedPages += 1;
      await degrade({ layer: "L1", trigger: "NVD malformed page", degradedOf: "partial", traceId, label: "NVD 响应结构不完整，拒绝推进覆盖游标", recoveryHint: "重试原窗口", emit });
      break;
    }
    const pageItems = data.vulnerabilities;
    items.push(...pageItems);
    pages += 1;
    const total = Number(data.totalResults);
    if (Number.isFinite(total)) totalResults = total;
    if (pageItems.length === 0) {
      empty = items.length === 0;
      if (items.length < totalResults) truncated = true;
      break;
    }
    if (items.length >= totalResults) break;
    if (pageIndex === MAX_PAGES_PER_WINDOW - 1) truncated = true;
  }

  return { kind, start, end, items, totalResults, pages, truncated, failedPages, empty };
}

/** 两窗口按 CVE 号合并去重（同一号可能既在 lastMod 又在 pubDate 窗口里）。 */
function mergeVulnerabilities(windows: WindowResult[]): { list: unknown[]; unique: number; dropped: number } {
  const byId = new Map<string, unknown>();
  let dropped = 0;
  for (const w of windows) {
    for (const entry of w.items) {
      const id = String((entry as { cve?: { id?: unknown } }).cve?.id ?? "");
      if (id === "" || byId.has(id)) {
        dropped += 1;
        continue;
      }
      byId.set(id, entry);
    }
  }
  return { list: [...byId.values()], unique: byId.size, dropped };
}

/** Inclusive adjacent endpoints deliberately overlap; mergeVulnerabilities deduplicates them. */
export function splitNvdWindow(start: string, end: string): Array<{ start: string; end: string }> {
  const from = Date.parse(start), to = Date.parse(end);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw new Error("Invalid NVD window: start must precede end");
  const result: Array<{ start: string; end: string }> = [];
  for (let cursor = from; cursor < to && result.length < MAX_SEGMENTS_PER_KIND; cursor += MAX_WINDOW_MS) {
    result.push({ start: new Date(cursor).toISOString(), end: new Date(Math.min(to, cursor + MAX_WINDOW_MS)).toISOString() });
  }
  return result;
}

function pubLookbackHours(): number {
  const raw = Number(process.env.SAFETRACE_NVD_PUB_LOOKBACK_HOURS ?? "");
  return Number.isFinite(raw) && raw > 0 && raw <= 120 * 24 ? raw : DEFAULT_PUB_LOOKBACK_H;
}

/**
 * 抓 NVD 的 lastMod + pubDate 两条窗口（各自翻页），合并去重后产出**一条** RawDoc。
 * 仍是一条 RawDoc 是为了不破坏 `SOURCE_RUNNERS` 的 `RawDoc | null` 契约；
 * 分页明细与各窗口计数都留在 payload_ref 文件里，可回溯可审计。
 */
export async function fetchNvd(opts: FetchNvdOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();

  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }

  const end = opts.window?.end ?? fetchedAt;
  const start = opts.window?.start ?? new Date(Date.parse(end) - LASTMOD_LOOKBACK_H * 3600_000).toISOString();
  const pubEnd = opts.pubWindow?.end ?? end;
  const pubStart = opts.pubWindow?.start ?? new Date(Date.parse(pubEnd) - pubLookbackHours() * 3600_000).toISOString();
  const apiKey = process.env.NVD_API_KEY?.trim() ?? "";

  const requests: Array<{ kind: WindowKind; start: string; end: string }> = [];
  if (opts.skipLastModWindow !== true) requests.push({ kind: "lastMod", start, end });
  if (opts.skipPubWindow !== true) requests.push({ kind: "pubDate", start: pubStart, end: pubEnd });
  if (!requests.length) throw new Error("NVD must query at least one window");
  // Validate EVERY requested range before making the first request.
  const segments = requests.map(w => ({ ...w, segments: splitNvdWindow(w.start, w.end) }));
  const windows: WindowResult[] = [];
  let unqueriedTail = false;
  for (const request of segments) {
    for (const segment of request.segments) windows.push(await fetchWindow(entry.url, apiKey, request.kind, segment.start, segment.end, traceId, opts.emit));
    const last = request.segments.at(-1)!;
    if (Date.parse(last.end) < Date.parse(request.end)) unqueriedTail = true;
  }
  const merged = mergeVulnerabilities(windows);
  const anyFailed = windows.some(w => w.failedPages > 0);
  // A genuine empty window is no_data, NOT a fixture replay and NOT a live success watermark.
  if (!merged.list.length && !anyFailed) opts.onNoData?.("NVD requested windows contain no records");
  const truncated = unqueriedTail || windows.some(w => w.truncated);
  const payload: Record<string, unknown> = {
    dataType: "NVD_CVE_MULTIWINDOW",
    coverage_complete: !anyFailed && !truncated,
    timestamp: fetchedAt,
    resultsPerPage: RESULTS_PER_PAGE,
    totalResults: merged.unique,
    vulnerabilities: merged.list,
    windows: windows.map((w) => ({
      kind: w.kind,
      start: w.start,
      end: w.end,
      pages_fetched: w.pages,
      reported_total: w.totalResults,
      items_from_window: w.items.length,
      truncated: w.truncated,
      failed_pages: w.failedPages,
      empty: w.empty,
    })),
    duplicate_entries_dropped: merged.dropped,
    ...(unqueriedTail ? { unqueried_tail: true, segment_limit: MAX_SEGMENTS_PER_KIND } : {}),
    ...(truncated
      ? {
          truncated: true,
          truncated_note: `单窗口翻页触顶 ${MAX_PAGES_PER_WINDOW} 页（${MAX_PAGES_PER_WINDOW * RESULTS_PER_PAGE} 条），本轮未取尽；不得推进成功游标，须重试或显式缩小补采窗口`,
        }
      : {}),
    ...(anyFailed ? { partial: true, partial_note: "有页抓取失败：仅保留成功部分，未用预置样本顶替" } : {}),
  };

  const payloadRef = await persistPayload(SOURCE_ID, payload, fetchedAt);
  const externalId =
    "nvd_pages=" + windows.map((w) => w.pages).join("+") +
    "_items=" + merged.unique +
    "_modwindow=" + nvdTs(start) + "~" + nvdTs(end);
  return buildRawDoc(payload, fetchedAt, payloadRef, externalId);
}
