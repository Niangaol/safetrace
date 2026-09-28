/**
 * Y2 · CISA KEV 适配器：每个 vulnerability 一条 IntelItem；
 * product/vendor 取 vendorProject/product 字段，version_range 从 shortDescription 推导（提不出则置空并告警）。
 */
import { SCHEMA_VERSION, nowIso } from "@safetrace/shared";
import type { IntelItem, RawDoc } from "@safetrace/shared";
import {
  CVE_PATTERN,
  makeIntelId,
  normalizeTs,
  readPayloadObject,
  str,
  strArray,
  type ParseResult,
} from "../common.js";

export const KEV_SOURCE_ID = "cisa_kev";
/** KEV 为政府权威源，初始可靠度权重从高。 */
export const KEV_RELIABILITY = 0.9;

/** 从 KEV shortDescription 提取显式版本约束（"<=2.14.1" 等）；提不到返回空（宁缺勿猜）。 */
function deriveVersionRange(text: string): string[] {
  const m = /(?:<=|>=|<|>)\s*\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?/.exec(text);
  return m ? [m[0].replace(/\s+/g, "")] : [];
}

export async function parseKev(raw: RawDoc): Promise<ParseResult> {
  const warnings: string[] = [];
  const payload = await readPayloadObject(raw, warnings);
  const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];
  if (vulnerabilities.length === 0) warnings.push("payload.vulnerabilities 缺失或为空，未产出 IntelItem");
  let cpesWarned = false;
  const items: IntelItem[] = [];
  for (const entry of vulnerabilities) {
    const v = entry as Record<string, unknown>;
    const cveId = str(v.cveID);
    if (cveId === "") {
      warnings.push("vulnerability 缺 cveID，跳过该条");
      continue;
    }
    if (!CVE_PATTERN.test(cveId)) warnings.push(cveId + " 不符合 CVE 编号格式（cve_ids pattern）");
    const summary = str(v.shortDescription);
    const product = str(v.product);
    const vendor = str(v.vendorProject);
    if (product === "") warnings.push(cveId + " 缺 product 字段，entities.product 置空");
    if (vendor === "") warnings.push(cveId + " 缺 vendorProject 字段，entities.vendor 置空");
    const cwe = strArray(v.cwes);
    if (cwe.length === 0) warnings.push(cveId + " 无 cwes 字段，entities.cwe 置空");
    if (!cpesWarned) {
      warnings.push("KEV 源不含 CPE 字段，entities.cpes 置空");
      cpesWarned = true;
    }
    const versionRange = deriveVersionRange(summary);
    if (versionRange.length === 0) warnings.push(cveId + " 无显式受影响版本字段，entities.version_range 置空");
    const pub = normalizeTs(v.dateAdded);
    if (pub.iso === null) warnings.push(cveId + " 缺 dateAdded 或不可解析，published_at 置空");
    else if (!pub.hadTz) warnings.push(cveId + " dateAdded 无时区后缀，已按 UTC 归一化");
    const rawTitle = str(v.vulnerabilityName);
    if (rawTitle === "") warnings.push(cveId + " 缺 vulnerabilityName，title 回退为 CVE 编号");
    items.push({
      intel_id: makeIntelId("kev", cveId),
      cve_ids: [cveId],
      source_ids: [KEV_SOURCE_ID],
      title: rawTitle === "" ? cveId : rawTitle,
      ...(summary === "" ? {} : { summary }),
      published_at: pub.iso ?? "",
      first_seen_at: nowIso(),
      entities: {
        product: product === "" ? null : product,
        vendor: vendor === "" ? null : vendor,
        version_range: versionRange,
        cwe,
        cpes: [],
      },
      raw_refs: [raw.payload_ref],
      source_reliability: KEV_RELIABILITY,
      schema_version: SCHEMA_VERSION,
    });
  }
  return { items, warnings };
}
