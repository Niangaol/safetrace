/**
 * Y2 · NVD CVE API 2.0 适配器：
 * descriptions → title/summary；weaknesses → entities.cwe；configurations.cpeMatch → cpes/product/vendor；
 * metrics（cvssMetricV31 等）与 references[] 在 IntelItem 契约中无承载字段，只登记 warning，留待 F 线回读 payload_ref。
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

export const NVD_SOURCE_ID = "nvd_cve";
/** NVD 为权威评分源，初始可靠度权重最高。 */
export const NVD_RELIABILITY = 0.95;

const TITLE_MAX = 120;

/** weaknesses[].description[].value → CWE 列表。 */
function weaknessValues(weaknesses: unknown[]): string[] {
  const out: string[] = [];
  for (const w of weaknesses) {
    const desc = (w as Record<string, unknown>).description;
    if (!Array.isArray(desc)) continue;
    for (const d of desc) {
      const value = str((d as Record<string, unknown>).value);
      if (value !== "") out.push(value);
    }
  }
  return out;
}

/** configurations[].nodes[].cpeMatch[].criteria（剔除 vulnerable=false 的非受影响项）。 */
function cpeCriteria(configurations: unknown[]): string[] {
  const out: string[] = [];
  for (const conf of configurations) {
    const nodes = (conf as Record<string, unknown>).nodes;
    if (!Array.isArray(nodes)) continue;
    for (const node of nodes) {
      const cpeMatch = (node as Record<string, unknown>).cpeMatch;
      if (!Array.isArray(cpeMatch)) continue;
      for (const m of cpeMatch) {
        const rec = m as Record<string, unknown>;
        if (rec.vulnerable === false) continue;
        const criteria = str(rec.criteria);
        if (criteria.startsWith("cpe:")) out.push(criteria);
      }
    }
  }
  return out;
}

/** 从 CPE 2.3 字符串解析 vendor/product（cpe:2.3:part:vendor:product:version:...）。 */
function cpeVendorProduct(cpe: string): { vendor: string | null; product: string | null } {
  const parts = cpe.split(":");
  const vendor = parts[3];
  const product = parts[4];
  const pick = (x: string | undefined): string | null => (x !== undefined && x !== "" && x !== "*" && x !== "-" ? x : null);
  return { vendor: pick(vendor), product: pick(product) };
}

export async function parseNvd(raw: RawDoc): Promise<ParseResult> {
  const warnings: string[] = [];
  const payload = await readPayloadObject(raw, warnings);
  const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];
  if (vulnerabilities.length === 0) warnings.push("payload.vulnerabilities 缺失或为空，未产出 IntelItem");
  let refsWarned = false;
  let metricsWarned = false;
  const items: IntelItem[] = [];
  for (const entry of vulnerabilities) {
    const cve = (entry as Record<string, unknown>).cve;
    if (typeof cve !== "object" || cve === null) {
      warnings.push("vulnerability 缺 cve 对象，跳过该条");
      continue;
    }
    const c = cve as Record<string, unknown>;
    const cveId = str(c.id);
    if (cveId === "") {
      warnings.push("cve.id 缺失，跳过该条");
      continue;
    }
    if (!CVE_PATTERN.test(cveId)) warnings.push(cveId + " 不符合 CVE 编号格式（cve_ids pattern）");
    const descriptions = Array.isArray(c.descriptions) ? c.descriptions : [];
    const en = descriptions.find((d) => (d as Record<string, unknown>).lang === "en") as Record<string, unknown> | undefined;
    const first = descriptions[0] as Record<string, unknown> | undefined;
    const desc = str(en?.value ?? first?.value);
    const clipped = clip(desc, TITLE_MAX);
    if (clipped.clipped) warnings.push(cveId + " 描述超长，title 截断至 " + TITLE_MAX + " 字符（原文见 payload_ref）");
    if (desc === "") warnings.push(cveId + " 无描述文本，title 回退为 CVE 编号");
    const pub = normalizeTs(c.published);
    if (pub.iso === null) warnings.push(cveId + " published 不可解析，published_at 置空");
    else if (!pub.hadTz) warnings.push(cveId + " published 无时区后缀，已按 UTC 归一化");
    const cwe = [...new Set(weaknessValues(Array.isArray(c.weaknesses) ? c.weaknesses : []))].filter((x) => /^CWE-\d+$/.test(x));
    if (cwe.length === 0) warnings.push(cveId + " 无 weaknesses/CWE，entities.cwe 置空");
    const cpes = [...new Set(cpeCriteria(Array.isArray(c.configurations) ? c.configurations : []))];
    const firstCpe = cpes[0];
    const vp = firstCpe === undefined ? { vendor: null, product: null } : cpeVendorProduct(firstCpe);
    if (cpes.length === 0) warnings.push(cveId + " 响应无 configurations/CPE，entities.product/vendor/cpes 置空");
    if (!metricsWarned && c.metrics !== undefined) {
      warnings.push("NVD metrics（cvssMetricV31 等）已读取但 IntelItem 契约无分数字段，留待 F4 富化回读 payload_ref");
      metricsWarned = true;
    }
    const references = Array.isArray(c.references) ? c.references : [];
    if (!refsWarned && references.length > 0) {
      warnings.push("references[].url 共 " + references.length + " 条外链未纳入 IntelItem（契约无字段），可经 payload_ref 回溯");
      refsWarned = true;
    }
    let item: IntelItem = {
      intel_id: makeIntelId("nvd", cveId),
      cve_ids: [cveId],
      source_ids: [NVD_SOURCE_ID],
      title: clipped.text === "" ? cveId : clipped.text,
      ...(desc === "" ? {} : { summary: desc }),
      published_at: pub.iso ?? "",
      first_seen_at: nowIso(),
      entities: { product: vp.product, vendor: vp.vendor, version_range: [], cwe, cpes },
      raw_refs: [raw.payload_ref],
      source_reliability: NVD_RELIABILITY,
      schema_version: SCHEMA_VERSION,
    };
    // vulnStatus 为 REJECTED/RESERVED/DISPUTED 时附 _cve_status，交由 DQ1 硬红线处置
    item = withCveStatus(item, str(c.vulnStatus));
    items.push(item);
  }
  return { items, warnings };
}
