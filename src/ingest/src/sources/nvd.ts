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
 * 礼貌与限流：无 `NVD_API_KEY` 时沿用 5 req/30s 令牌桶（每一页都过桶）；有 key 直发。
 * 只使用 NVD 官方参数，不塞自定义 query（自定义参数可能被判 400，且会污染复现命令）。
 *
 * 降级红线：
 *  - 两窗口都彻底取不到数据 ⇒ `degradeToFixture`，`external_id` 以 `_fixture` 结尾（时效看板据此剔除该行）；
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

/** 进程内令牌桶时间戳（仅无 key 慢速模式；离线/测试路径不触发）。 */
const requestTimes: number[] = [];

async function acquireNoKeyToken(): Promise<void> {
  const now = Date.now();
  while (requestTimes.length > 0 && (requestTimes[0] ?? 0) <= now - NO_KEY_WINDOW_MS) requestTimes.shift();
  if (requestTimes.length >= NO_KEY_CAPACITY) {
    const oldest = requestTimes[0] ?? now;
    await sleep(Math.max(0, oldest + NO_KEY_WINDOW_MS - now));
    await acquireNoKeyToken();
    return;
  }
  requestTimes.push(now);
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

  for (let pageIndex = 0; pageIndex < MAX_PAGES_PER_WINDOW; pageIndex += 1) {
    const startIndex = pageIndex * RESULTS_PER_PAGE;
    const url =
      baseUrl +
      "?" + startKey + "=" + encodeURIComponent(start) +
      "&" + endKey + "=" + encodeURIComponent(end) +
      "&resultsPerPage=" + RESULTS_PER_PAGE +
      "&startIndex=" + startIndex;
    if (apiKey === "") await acquireNoKeyToken();
    const attempt = await fetchJsonWithRetry(url, { headers: apiKey === "" ? {} : { apiKey } });

    if (!attempt.ok) {
      if (attempt.reason.includes("HTTP 404")) {
        empty = true; // NVD 官方语义：该窗口没有结果
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

    const data = attempt.data as Record<string, unknown>;
    const pageItems = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    items.push(...pageItems);
    pages += 1;
    const total = Number(data.totalResults);
    if (Number.isFinite(total)) totalResults = total;
    if (pageItems.length === 0) {
      empty = true;
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

function pubLookbackHours(): number {
  const raw = Number(process.env.SAFETRACE_NVD_PUB_LOOKBACK_HOURS ?? "");
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_PUB_LOOKBACK_H;
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

  const windows: WindowResult[] = opts.skipLastModWindow === true ? [] : [
    await fetchWindow(entry.url, apiKey, "lastMod", start, end, traceId, opts.emit),
  ];
  if (opts.skipPubWindow !== true) {
    windows.push(await fetchWindow(entry.url, apiKey, "pubDate", pubStart, pubEnd, traceId, opts.emit));
  }

  const merged = mergeVulnerabilities(windows);
  const anyFailed = windows.some((w) => w.failedPages > 0);

  if (merged.list.length === 0 && !anyFailed) {
    // 两窗口都空是异常态（NVD 不可能 48h 没有任何新发布），显式降级而不是静默
    await degradeToFixture("NVD lastMod 与 pubDate 窗口同时无结果", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }

  const truncated = windows.some((w) => w.truncated);
  const payload: Record<string, unknown> = {
    dataType: "NVD_CVE_MULTIWINDOW",
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
    ...(truncated
      ? {
          truncated: true,
          truncated_note: `单窗口翻页触顶 ${MAX_PAGES_PER_WINDOW} 页（${MAX_PAGES_PER_WINDOW * RESULTS_PER_PAGE} 条），本轮未取尽；下一轮窗口重叠会补`,
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
