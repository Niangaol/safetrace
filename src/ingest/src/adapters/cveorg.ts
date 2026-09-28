/**
 * Y2 · cve.org（CVE 5 JSON，containers.cna）适配器：
 * cveMetadata → cve_ids/published_at/_cve_status；cna.title/descriptions → title/summary；
 * cna.affected[].versions → version_range；cna.problemTypes → cwe；
 * cna.metrics 与 cna.references 在 IntelItem 契约中无承载字段，只登记 warning。
 */
import { SCHEMA_VERSION, nowIso } from "@safetrace/shared";
import type { IntelItem, RawDoc } from "@safetrace/shared";
import {
  CVE_PATTERN,
  clip,
  makeIntelId,
  normalizeTs,
  readPayloadObject,
  str,
  withCveStatus,
  type ParseResult,
} from "../common.js";

export const CVEORG_SOURCE_ID = "cve_org";
/** CNA 权威源，初始可靠度权重与 NVD 同档。 */
export const CVEORG_RELIABILITY = 0.95;

const TITLE_MAX = 120;

/** 取 descriptions 中优先 en 的文本。 */
function pickDescription(descriptions: unknown): string {
  if (!Array.isArray(descriptions)) return "";
  const en = descriptions.find((d) => (d as Record<string, unknown>).lang === "en") as Record<string, unknown> | undefined;
  const first = descriptions[0] as Record<string, unknown> | undefined;
  return str(en?.value ?? first?.value);
}

/** affected[].versions → version_range（lessThan/lessThanOrEqual/version 三种写法），并取首个非空 vendor/product。 */
function affectedToEntities(affected: unknown[]): {
  versionRange: string[];
  vendor: string | null;
  product: string | null;
} {
  const ranges: string[] = [];
  let vendor: string | null = null;
  let product: string | null = null;
  for (const a of affected) {
    const rec = a as Record<string, unknown>;
    if (vendor === null) {
      const x = str(rec.vendor);
      if (x !== "") vendor = x;
    }
    if (product === null) {
      const x = str(rec.product);
      if (x !== "") product = x;
    }
    const versions = rec.versions;
    if (!Array.isArray(versions)) continue;
    for (const ver of versions) {
      const v = ver as Record<string, unknown>;
      const lessThan = str(v.lessThan);
      const lessThanOrEqual = str(v.lessThanOrEqual);
      const version = str(v.version);
      const status = str(v.status);
      if (lessThanOrEqual !== "") ranges.push("<=" + lessThanOrEqual);
      else if (lessThan !== "") ranges.push("<" + lessThan);
      else if (version !== "" && status === "affected") ranges.push(version);
    }
  }
  return { versionRange: [...new Set(ranges)], vendor, product };
}

/** problemTypes[].descriptions[].cweId → CWE 列表。 */
function problemTypeCwes(problemTypes: unknown): string[] {
  if (!Array.isArray(problemTypes)) return [];
  const out: string[] = [];
  for (const pt of problemTypes) {
    const descriptions = (pt as Record<string, unknown>).descriptions;
    if (!Array.isArray(descriptions)) continue;
    for (const d of descriptions) {
      const id = str((d as Record<string, unknown>).cweId);
      if (/^CWE-\d+$/.test(id)) out.push(id);
    }
  }
  return [...new Set(out)];
}

export async function parseCveOrg(raw: RawDoc): Promise<ParseResult> {
  const warnings: string[] = [];
  const payload = await readPayloadObject(raw, warnings);
  const meta = (payload.cveMetadata ?? {}) as Record<string, unknown>;
  const containers = (payload.containers ?? {}) as Record<string, unknown>;
  const cna = (containers.cna ?? {}) as Record<string, unknown>;
  const cveId = str(meta.cveId);
  if (cveId === "") {
    warnings.push("cveMetadata.cveId 缺失，跳过该条");
    return { items: [], warnings };
  }
  if (!CVE_PATTERN.test(cveId)) warnings.push(cveId + " 不符合 CVE 编号格式（cve_ids pattern）");
  const state = str(meta.state);
  if (state !== "" && state !== "PUBLISHED") warnings.push(cveId + " cveMetadata.state=" + state + "（非 PUBLISHED，已附 _cve_status 交 DQ1）");
  const desc = pickDescription(cna.descriptions);
  if (desc === "" && str(cna.title) === "") warnings.push(cveId + " cna 无 title/descriptions，title 回退为 CVE 编号");
  const cnaTitle = str(cna.title);
  const title = cnaTitle !== "" ? cnaTitle : (clip(desc, TITLE_MAX).text || cveId);
  const pub = normalizeTs(meta.datePublished);
  if (pub.iso === null) warnings.push(cveId + " datePublished 不可解析，published_at 置空");
  else if (!pub.hadTz) warnings.push(cveId + " datePublished 无时区后缀，已按 UTC 归一化");
  const affected: unknown[] = Array.isArray(cna.affected) ? cna.affected : [];
  const { versionRange, vendor, product } = affectedToEntities(affected);
  if (affected.length === 0) warnings.push(cveId + " 无 cna.affected，entities.product/vendor/version_range 置空");
  const cwe = problemTypeCwes(cna.problemTypes);
  if (cwe.length === 0) warnings.push(cveId + " 无 problemTypes/CWE，entities.cwe 置空");
  const metrics = cna.metrics;
  if (Array.isArray(metrics) && metrics.length > 0) {
    warnings.push("cna.metrics（CVSS）已读取但 IntelItem 契约无分数字段，留待 F4 富化回读 payload_ref");
  }
  const references = cna.references;
  if (Array.isArray(references) && references.length > 0) {
    warnings.push("cna.references[].url 共 " + references.length + " 条外链未纳入 IntelItem（契约无字段），可经 payload_ref 回溯");
  }
  let item: IntelItem = {
    intel_id: makeIntelId("cveorg", cveId),
    cve_ids: [cveId],
    source_ids: [CVEORG_SOURCE_ID],
    title,
    ...(desc === "" ? {} : { summary: desc }),
    published_at: pub.iso ?? "",
    first_seen_at: nowIso(),
    entities: {
      product,
      vendor,
      version_range: versionRange,
      cwe,
      cpes: [],
    },
    raw_refs: [raw.payload_ref],
    source_reliability: CVEORG_RELIABILITY,
    schema_version: SCHEMA_VERSION,
  };
  item = withCveStatus(item, state);
  return { items: [item], warnings };
}
