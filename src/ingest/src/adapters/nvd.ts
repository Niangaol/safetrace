/**
 * Y2 · NVD CVE API 2.0 适配器：
 * descriptions → title/summary；weaknesses → entities.cwe；
 * configurations.cpeMatch → cpes/product/vendor，且 versionStart/End* 与 version 边界 → entities.version_range
 * （与 cveorg/OSV 同文本格式，F2 资产匹配的 parseRange 可直接解析；提不出的不猜，置空并留痕）；
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

interface CpeMatch {
  criteria: string;
  version: string;
  startIncluding: string;
  startExcluding: string;
  endIncluding: string;
  endExcluding: string;
}

/** configurations[].nodes[].cpeMatch[]（剔除 vulnerable=false 的非受影响项）。 */
function cpeMatches(configurations: unknown[]): CpeMatch[] {
  const out: CpeMatch[] = [];
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
        if (!criteria.startsWith("cpe:")) continue;
        out.push({
          criteria,
          version: str(rec.version),
          startIncluding: str(rec.versionStartIncluding),
          startExcluding: str(rec.versionStartExcluding),
          endIncluding: str(rec.versionEndIncluding),
          endExcluding: str(rec.versionEndExcluding),
        });
      }
    }
  }
  return out;
}

/** 版本边界字面量：只接受数字点分版本（可带 v 前缀）；通配符与预发布混排不猜，返回 null。 */
function versionLiteral(value: string): string | null {
  const match = /^v?(\d+(?:\.\d+){0,7})$/.exec(value.trim());
  return match ? (match[1] ?? null) : null;
}

/**
 * cpeMatch 版本边界 → version_range 文本（与 cveorg/OSV 同格式，F2 parseRange 可直接解析）：
 * - 精确 version（非通配）→ 裸版本字面量（等价 =a），优先于边界；
 * - start/end 四类边界 → ">=a <b" 组合（同一 match 内 AND，数组多条间 OR）；
 * - 边界含通配符/非数字时该边界跳过，整条提不出则不留（不臆造区间）。
 */
function versionRangesFromCpe(matches: readonly CpeMatch[]): string[] {
  const ranges: string[] = [];
  for (const m of matches) {
    const exact = versionLiteral(m.version);
    if (exact !== null) {
      ranges.push(exact);
      continue;
    }
    const tokens: string[] = [];
    const startIncluding = versionLiteral(m.startIncluding);
    const startExcluding = versionLiteral(m.startExcluding);
    const endIncluding = versionLiteral(m.endIncluding);
    const endExcluding = versionLiteral(m.endExcluding);
    if (startIncluding !== null) tokens.push(">=" + startIncluding);
    if (startExcluding !== null) tokens.push(">" + startExcluding);
    if (endIncluding !== null) tokens.push("<=" + endIncluding);
    if (endExcluding !== null) tokens.push("<" + endExcluding);
    if (tokens.length > 0) ranges.push(tokens.join(" "));
  }
  return [...new Set(ranges)];
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
  // 翻页/多窗口的覆盖情况必须进 warning：否则"只取了一部分"看起来像取完了（红线：截断要说出口）
  if (payload.truncated === true) warnings.push("NVD 翻页触顶未取尽：" + str(payload.truncated_note) );
  if (payload.partial === true) warnings.push("NVD 部分页抓取失败：" + str(payload.partial_note));
  if (Number(payload.duplicate_entries_dropped) > 0) {
    warnings.push("NVD lastMod 与 pubDate 窗口重叠，去重丢弃 " + String(payload.duplicate_entries_dropped) + " 条");
  }
  if (Array.isArray(payload.windows)) {
    for (const w of payload.windows as Record<string, unknown>[]) {
      const failed = Number(w.failed_pages) > 0 ? "，失败 " + String(w.failed_pages) + " 页" : "";
      const empt = w.empty === true ? "，该窗口无结果" : "";
      warnings.push(
        "NVD 窗口 " + String(w.kind) + "：" + String(w.pages_fetched) + " 页 / 上游报 " + String(w.reported_total) +
          " 条 / 本轮取 " + String(w.items_from_window) + " 条" + empt + failed,
      );
    }
  }
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
    const cpeMatchList = cpeMatches(Array.isArray(c.configurations) ? c.configurations : []);
    const cpes = [...new Set(cpeMatchList.map((m) => m.criteria))];
    const versionRange = versionRangesFromCpe(cpeMatchList);
    const firstCpe = cpes[0];
    const vp = firstCpe === undefined ? { vendor: null, product: null } : cpeVendorProduct(firstCpe);
    if (cpes.length === 0) warnings.push(cveId + " 响应无 configurations/CPE，entities.product/vendor/cpes 置空");
    if (cpes.length > 0 && versionRange.length === 0) {
      warnings.push(cveId + " CPE 无可解析版本边界，entities.version_range 置空");
    }
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
      entities: { product: vp.product, vendor: vp.vendor, version_range: versionRange, cwe, cpes },
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
