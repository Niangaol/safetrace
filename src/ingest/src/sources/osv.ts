/**
 * Y1 · OSV 采集器：POST /v1/querybatch 批量包查询（body {queries:[{package?...}]}）；
 * 也可按 CVE 列表逐条 GET /v1/vulns/{id}（OSV 记录可被 CVE 别名解析），合并为 querybatch 同构结果。
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

const SOURCE_ID = "osv";
const FIXTURE = "fixtures/sources/osv.sample.json";

/** OSV querybatch 查询单元（package 必填其一，version 可选）。 */
export interface OsvPackageQuery {
  package?: { ecosystem: string; name: string };
  version?: string;
}

export interface FetchOsvOpts extends FetchOpts {
  /** 包查询列表（POST querybatch）。 */
  queries?: OsvPackageQuery[];
  /** CVE 列表（逐条 GET /v1/vulns/{id}，OSV 支持别名解析）。 */
  cveIds?: string[];
}

/** 从登记的 querybatch URL 反推 OSV 站点基址（https://api.osv.dev）。 */
function osvBase(entryUrl: string): string {
  const i = entryUrl.indexOf("/v1/");
  return i > 0 ? entryUrl.slice(0, i) : entryUrl;
}

function buildRawDoc(payload: unknown, fetchedAt: string, payloadRef: string, externalId: string, etag?: string): RawDoc {
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

/** 抓取 OSV：离线/失败回放预置样本；无查询目标时返回 null（不发起请求，非降级路径）。 */
export async function fetchOsv(opts: FetchOsvOpts = {}): Promise<RawDoc | null> {
  const entry = requireSource(SOURCE_ID);
  const traceId = opts.traceId ?? nextId("tr");
  const fetchedAt = nowIso();
  if (opts.offline === true || isOfflineEnv()) {
    await degradeToFixture("OFFLINE_FIXTURES=true", traceId, opts.emit);
    return buildRawDoc(await readJsonFile(FIXTURE), fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const queries = opts.queries ?? [];
  const cveIds = (opts.cveIds ?? []).filter((x) => x.trim() !== "");
  if (queries.length === 0 && cveIds.length === 0) return null;

  if (queries.length > 0) {
    const attempt = await fetchJsonWithRetry(entry.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
    });
    if (!attempt.ok) {
      await degradeToFixture("OSV querybatch 连续失败：" + attempt.reason, traceId, opts.emit);
      return buildRawDoc(await readJsonFile(FIXTURE), fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
    }
    const names = queries.map((q) => q.package?.name ?? "pkg").join("_");
    const payloadRef = await persistPayload(SOURCE_ID, attempt.data, fetchedAt);
    return buildRawDoc(attempt.data, fetchedAt, payloadRef, "osv_query_" + names, attempt.etag);
  }

  // CVE 列表：逐条 GET，成功记录合并成 {results:[{vulns:[...]}]}
  const results: unknown[] = [];
  for (const id of cveIds) {
    const attempt = await fetchJsonWithRetry(osvBase(entry.url) + "/v1/vulns/" + encodeURIComponent(id));
    if (attempt.ok) results.push({ vulns: [attempt.data] });
  }
  if (results.length === 0) {
    await degradeToFixture("OSV CVE 列表连续失败：" + cveIds.join(","), traceId, opts.emit);
    return buildRawDoc(await readJsonFile(FIXTURE), fetchedAt, FIXTURE, SOURCE_ID + "_fixture");
  }
  const payload = { results };
  const payloadRef = await persistPayload(SOURCE_ID, payload, fetchedAt);
  return buildRawDoc(payload, fetchedAt, payloadRef, "osv_cve_" + cveIds.join("-"));
}
