/** 仅解析原始报文显式结构字段。出处/hash/DQ 门禁由 knowledge-projection 外层负责。 */
import type { ScoreSource } from "@safetrace/shared";
export interface RawVersionFact { product: string; vendor: string | null; version_range: string[] }
export interface RawScoreFact { cve_id: string; source: ScoreSource; score: number; vector: string }
const unsupported = "unsupported_version_rule";
export function cnaVersionFacts(container: any): RawVersionFact[] {
  return (Array.isArray(container?.affected) ? container.affected : []).flatMap((a: any) => {
    if (typeof a.product !== "string" || !a.product.trim()) return [];
    const rows = Array.isArray(a.versions) ? a.versions : [];
    const invalid = a.defaultStatus === "affected" || rows.some((v: any) => v.changes?.length || !["affected", "unaffected"].includes(v.status));
    const rules = rows.filter((v: any) => v.status === "affected").map((v: any) => {
      if (typeof v.version !== "string" || !v.version.trim() || v.version === "*") return unsupported;
      if (typeof v.lessThan === "string") return ">=" + v.version + " <" + v.lessThan;
      if (typeof v.lessThanOrEqual === "string") return ">=" + v.version + " <=" + v.lessThanOrEqual;
      return "=" + v.version;
    });
    // 排除区间/default/changes 复杂语义未实现时不硬判安全或受影响。
    const excludes = rows.some((v: any) => v.status === "unaffected");
    return [{ product: a.product, vendor: typeof a.vendor === "string" ? a.vendor : null,
      version_range: invalid || excludes ? [unsupported] : rules }];
  });
}
export function nvdVersionFacts(cve: any): RawVersionFact[] {
  const out: RawVersionFact[] = [];
  const walk = (n: any, complex: boolean) => {
    if (!n || typeof n !== "object") return;
    complex ||= n.operator === "AND" || n.negate === true;
    for (const m of Array.isArray(n.cpeMatch) ? n.cpeMatch : []) {
      if (m.vulnerable !== true || typeof m.criteria !== "string") continue;
      const parts = m.criteria.split(":");
      if (parts.length < 6 || parts[0] !== "cpe" || parts[1] !== "2.3") continue;
      const bounds: string[] = [];
      for (const [field, op] of [["versionStartIncluding", ">="], ["versionStartExcluding", ">"], ["versionEndIncluding", "<="], ["versionEndExcluding", "<"]]) {
        if (typeof m[field!] === "string") bounds.push(op + m[field!]);
      }
      if (!bounds.length && parts[5] !== "*" && parts[5] !== "-") bounds.push("=" + parts[5]);
      out.push({ product: parts[4]!.replace(/_/g, " "), vendor: parts[3] ?? null,
        version_range: complex ? [unsupported] : bounds.length ? [bounds.join(" ")] : [unsupported] });
    }
    for (const child of [...(Array.isArray(n.nodes) ? n.nodes : []), ...(Array.isArray(n.children) ? n.children : [])]) walk(child, complex);
  };
  for (const config of Array.isArray(cve?.configurations) ? cve.configurations : []) walk(config, false);
  return out;
}
export function recordScoreFacts(record: { id: string; metrics: any[] }): RawScoreFact[] {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(record.id)) return [];
  return record.metrics.flatMap(m => {
    if (!["nvd", "cna", "ghsa", "adp"].includes(m?.source_of_score) || typeof m.baseScore !== "number" || !Number.isFinite(m.baseScore) || m.baseScore < 0 || m.baseScore > 10 || typeof m.vectorString !== "string" || !m.vectorString.startsWith("CVSS:3.1/")) return [];
    return [{ cve_id: record.id.toUpperCase(), source: m.source_of_score as ScoreSource, score: m.baseScore, vector: m.vectorString }];
  });
}
