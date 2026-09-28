/**
 * Y1 · cve.org（CVE Program AWG API）采集器：按 CVE ID 单条 GET；
 * 全量/变更流（cvelistV5 git 差分）属 Y4 漏报补偿，P0 先只做单条查询。
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

const SOURCE_ID = "cve_org";
const FIXTURE = "fixtures/sources/cveorg.sample.json";

export interface FetchCveOrgOpts extends FetchOpts {
  /** 目标 CVE ID（单条 GET 的主键）；缺省且非离线时返回 null（不发起请求，非降级路径）。 */
  cveId?: string;
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

/** 抓取单条 CVE 记录；离线或失败时回放预置样本（显式降级）。 */
export async function fetchCveOrg(opts: FetchCveOrgOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();
  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const cveId = (opts.cveId ?? "").trim();
  if (cveId === "") return null;
  const attempt = await fetchJsonWithRetry(entry.url + encodeURIComponent(cveId));
  if (!attempt.ok) {
    await degradeToFixture("cve.org 连续抓取失败：" + attempt.reason, traceId, opts.emit);
    const payload = (await readJsonFile(FIXTURE)) as Record<string, unknown>;
    return buildRawDoc(payload, fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const payloadRef = await persistPayload(SOURCE_ID, attempt.data, fetchedAt);
  return buildRawDoc(attempt.data as Record<string, unknown>, fetchedAt, payloadRef, cveId, attempt.etag);
}
