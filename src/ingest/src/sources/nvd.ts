/**
 * Y1 · NVD CVE API 2.0 采集器：lastModStartDate/lastModEndDate 增量窗口；
 * 无 NVD_API_KEY 时走 5req/30s 令牌桶慢速模式，有 key 时直接请求（NVD 侧放宽到 50req/30s）。
 */
import { nextId, nowIso } from "@safetrace/shared";
import type { RawDoc } from "@safetrace/shared";
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

export interface FetchNvdOpts extends FetchOpts {
  /** 增量窗口（ISO-8601，NVD 2.0 要求带时区）；缺省取最近 24 小时。 */
  window?: { start: string; end: string };
}

function buildRawDoc(payload: Record<string, unknown>, fetchedAt: string, payloadRef: string, externalId: string, etag?: string): RawDoc {
  const entry = requireSource(SOURCE_ID);
  return {
    source_id: SOURCE_ID,
    source_type: entry.source_type,
    external_id: externalId,
    url: entry.url,
    fetched_at: fetchedAt,
    content_type: "json",
    payload_ref: payloadRef,
    ...(etag ? { http_etag: etag } : {}),
  };
}

/** 抓取 NVD 增量窗口；离线或失败时回放预置样本（显式降级）。 */
export async function fetchNvd(opts: FetchNvdOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();
  const end = opts.window?.end ?? new Date().toISOString();
  const start = opts.window?.start ?? new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const windowId = "nvd_window_" + start + "_" + end;
  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const apiKey = process.env.NVD_API_KEY?.trim() ?? "";
  if (apiKey === "") await acquireNoKeyToken();
  const url = entry.url + "?lastModStartDate=" + encodeURIComponent(start) + "&lastModEndDate=" + encodeURIComponent(end);
  const attempt = await fetchJsonWithRetry(url, { headers: apiKey === "" ? {} : { apiKey } });
  if (!attempt.ok) {
    await degradeToFixture("NVD 连续抓取失败：" + attempt.reason, traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const payloadRef = await persistPayload(SOURCE_ID, attempt.data, fetchedAt);
  return buildRawDoc(attempt.data as Record<string, unknown>, fetchedAt, payloadRef, windowId, attempt.etag);
}
