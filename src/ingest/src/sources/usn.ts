/**
 * Y1 · Ubuntu 安全公告（USN）采集器 —— 监测线第 7 源（E-01，source_type=vendor_advisory）。
 *
 * 口径与纪律：
 * - 只读官方公开 JSON 接口 `https://ubuntu.com/security/notices.json`，免 key、免登录、不提交任何表单；
 * - 礼貌爬取：固定 User-Agent（SAFETRACE_UA 可覆盖）、单次 limit 上限、按 registry 的 rate_per_min 限频；
 *   ubuntu.com/robots.txt 对 `*` 声明 `Crawl-delay: 1` 且 `Allow: /security`，本采集器的轮询间隔远大于 1s；
 * - 离线或连续失败时回放 `fixtures/sources/usn.sample.json`，并一律经 shared.degrade() 显式登记
 *   （红线：禁止静默兜底，响应带 degraded_to=fixture）。
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
  type FetchOpts,
} from "../common.js";

const SOURCE_ID = "ubuntu_usn";
const FIXTURE = "fixtures/sources/usn.sample.json";

/** 礼貌上限：单轮最多取多少条公告（默认 20，硬上限 100）。 */
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

/** 固定 UA（TEAM-PLAN §3.3 纪律 2：禁止伪装浏览器、必须可识别）。 */
export function userAgent(): string {
  const fromEnv = process.env.SAFETRACE_UA?.trim();
  return fromEnv !== undefined && fromEnv !== ""
    ? fromEnv
    : "SafeTrace/0.1 (academic competition crawler; vulnerability advisory read-only polling)";
}

function buildRawDoc(
  payload: Record<string, unknown>,
  fetchedAt: string,
  payloadRef: string,
  externalId: string,
  etag?: string,
): RawDoc {
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

export interface FetchUsnOpts extends FetchOpts {
  /** 本轮取多少条最新公告（缺省 20，上限 100）。 */
  limit?: number;
}

/**
 * 抓取最新 USN 公告列表。
 * 返回 null 只发生在「离线样本也读不到」的异常路径；离线/失败回放走显式降级。
 */
export async function fetchUsn(opts: FetchUsnOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();
  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }

  const raw = opts.limit ?? DEFAULT_LIMIT;
  const limit = Math.max(1, Math.min(MAX_LIMIT, Math.trunc(raw)));
  const url = entry.url + "?limit=" + limit + "&order=newest";
  const attempt = await fetchJsonWithRetry(url, { headers: { "User-Agent": userAgent() } });
  if (!attempt.ok) {
    await degradeToFixture("USN 连续抓取失败：" + attempt.reason, traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }

  const payload = attempt.data as Record<string, unknown>;
  const notices = Array.isArray(payload.notices) ? payload.notices : [];
  const first = notices[0] as Record<string, unknown> | undefined;
  const last = notices[notices.length - 1] as Record<string, unknown> | undefined;
  // external_id 取本轮列表的首尾公告号，便于同一批次的幂等回放
  const firstId = typeof first?.id === "string" ? first.id : "empty";
  const lastId = typeof last?.id === "string" ? last.id : "empty";
  const payloadRef = await persistPayload(SOURCE_ID, payload, fetchedAt);
  return buildRawDoc(payload, fetchedAt, payloadRef, "usn_" + firstId + "_" + lastId, attempt.etag);
}
