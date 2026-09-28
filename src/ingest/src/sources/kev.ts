/**
 * Y1 · CISA KEV 采集器：单文件全量 JSON；成功时落盘缓存（带 fetched_at），
 * OFFLINE_FIXTURES=true 或连续失败后回放预置样本（显式降级，degraded_to=fixture）。
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

const SOURCE_ID = "cisa_kev";
const FIXTURE = "fixtures/sources/kev.sample.json";

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

/** 抓取 KEV 全量目录。离线或失败时回放 fixtures 样本并经 degrade() 登记。 */
export async function fetchKev(opts: FetchOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();
  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const attempt = await fetchJsonWithRetry(entry.url);
  if (!attempt.ok) {
    await degradeToFixture("KEV 连续抓取失败：" + attempt.reason, traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const payload = attempt.data as Record<string, unknown>;
  const version = typeof payload.catalogVersion === "string" && payload.catalogVersion.trim() !== ""
    ? payload.catalogVersion.trim()
    : "catalog";
  const payloadRef = await persistPayload(SOURCE_ID, payload, fetchedAt);
  return buildRawDoc(payload, fetchedAt, payloadRef, "kev_" + version, attempt.etag);
}
