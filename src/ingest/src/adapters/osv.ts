/**
 * Y2 · OSV 适配器：querybatch 同构结果 results[].vulns[]（兼容单条 GET /v1/vulns/{id} 响应）；
 * aliases 按 CVE/GHSA 口径分拣，affected[].ranges[].events → version_range。
 */
import { SCHEMA_VERSION, nowIso } from "@safetrace/shared";
import type { IntelItem, RawDoc } from "@safetrace/shared";
import { makeIntelId, normalizeTs, readPayloadObject, str, strArray, type ParseResult } from "../common.js";

export const OSV_SOURCE_ID = "osv";
/** OSV 为社区聚合源，初始可靠度权重低于 NVD/KEV。 */
export const OSV_RELIABILITY = 0.85;

/** 收集 vuln 列表：单条响应（带 id）或 querybatch 的 results[].vulns。 */
function collectVulns(payload: Record<string, unknown>): unknown[] {
  if (typeof payload.id === "string") return [payload];
  const out: unknown[] = [];
  for (const r of Array.isArray(payload.results) ? payload.results : []) {
    const vulns = (r as Record<string, unknown>).vulns;
    if (Array.isArray(vulns)) out.push(...vulns);
  }
  return out;
}

/** ECOSYSTEM/SEMVER range events → ">=introduced <fixed" 形式；introduced=0 视为无下界。 */
function rangesToText(affected: unknown[]): string[] {
  const out: string[] = [];
  for (const a of affected) {
    const ranges = (a as Record<string, unknown>).ranges;
    if (!Array.isArray(ranges)) continue;
    for (const r of ranges) {
      const events = (r as Record<string, unknown>).events;
      if (!Array.isArray(events)) continue;
      let introduced: string | null = null;
      let fixed: string | null = null;
      for (const e of events) {
        const rec = e as Record<string, unknown>;
        const i = str(rec.introduced);
        const f = str(rec.fixed);
        if (i !== "" && introduced === null) introduced = i;
        if (f !== "" && fixed === null) fixed = f;
      }
      const parts: string[] = [];
      if (introduced !== null && introduced !== "0") parts.push(">=" + introduced);
      if (fixed !== null) parts.push("<" + fixed);
      if (parts.length > 0) out.push(parts.join(" "));
    }
  }
  return [...new Set(out)];
}

export async function parseOsv(raw: RawDoc): Promise<ParseResult> {
  const warnings: string[] = [];
  const payload = await readPayloadObject(raw, warnings);
  const vulns = collectVulns(payload);
  if (vulns.length === 0) warnings.push("payload.results[].vulns 缺失或为空，未产出 IntelItem");
  let severityWarned = false;
  let cweWarned = false;
  let vendorWarned = false;
  const items: IntelItem[] = [];
  for (const entry of vulns) {
    const v = entry as Record<string, unknown>;
    const osvId = str(v.id);
    if (osvId === "") {
      warnings.push("vuln 缺 id，跳过该条");
      continue;
    }
    const cveIds: string[] = [];
    const ghsaIds: string[] = [];
    const aliases: string[] = [];
    if (osvId.startsWith("GHSA-")) ghsaIds.push(osvId);
    for (const a of strArray(v.aliases)) {
      if (/^CVE-[0-9]{4}-[0-9]{4,}$/.test(a)) cveIds.push(a);
      else if (a.startsWith("GHSA-")) ghsaIds.push(a);
      else aliases.push(a);
    }
    if (cveIds.length === 0) warnings.push(osvId + " 无 CVE 别名，cve_ids 置空（与 KEV/NVD 归并需靠 ghsa_ids/osv_ids）");
    const summary = str(v.details);
    const osvSummary = str(v.summary);
    if (osvSummary === "") warnings.push(osvId + " 无 summary，title 回退为 OSV ID");
    const pub = normalizeTs(v.published);
    if (pub.iso === null) warnings.push(osvId + " published 不可解析，published_at 置空");
    else if (!pub.hadTz) warnings.push(osvId + " published 无时区后缀，已按 UTC 归一化");
    const affected: unknown[] = Array.isArray(v.affected) ? v.affected : [];
    const pkg = affected[0] as Record<string, unknown> | undefined;
    const pkgName = str((pkg?.package as Record<string, unknown> | undefined)?.name);
    if (pkgName === "") warnings.push(osvId + " 无 affected[].package，entities.product 置空");
    if (!vendorWarned) {
      warnings.push("OSV 包名无法可靠反推 vendor，entities.vendor 置空");
      vendorWarned = true;
    }
    if (!cweWarned) {
      warnings.push("OSV 源无 CWE 字段，entities.cwe 置空");
      cweWarned = true;
    }
    if (!severityWarned && Array.isArray(v.severity) && v.severity.length > 0) {
      warnings.push("OSV severity[].score（CVSS 向量）已读取但 IntelItem 契约无分数字段，留待 F4 富化");
      severityWarned = true;
    }
    items.push({
      intel_id: makeIntelId("osv", osvId),
      cve_ids: [...new Set(cveIds)],
      ...(ghsaIds.length > 0 ? { ghsa_ids: [...new Set(ghsaIds)] } : {}),
      osv_ids: [osvId],
      ...(aliases.length > 0 ? { aliases: [...new Set(aliases)] } : {}),
      source_ids: [OSV_SOURCE_ID],
      title: osvSummary === "" ? osvId : osvSummary,
      ...(summary === "" ? {} : { summary }),
      published_at: pub.iso ?? "",
      first_seen_at: nowIso(),
      entities: {
        product: pkgName === "" ? null : pkgName,
        vendor: null,
        version_range: rangesToText(affected),
        cwe: [],
        cpes: [],
      },
      raw_refs: [raw.payload_ref],
      source_reliability: OSV_RELIABILITY,
      schema_version: SCHEMA_VERSION,
    });
  }
  return { items, warnings };
}
