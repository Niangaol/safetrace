/** 从通过原文/hash/DQ 门禁的逐记录事实派生 live 问答证据；不读侧边历史无证明结果。 */
import { sha256Json } from "@safetrace/shared";
import type { EvidenceChunk, IntelItem, SourceConflict } from "@safetrace/shared";
import type { ProjectedEvidence } from "./knowledge-projection.js";
import type { VersionImpactQuery, VersionImpactAnswer } from "./version-impact.js";
import { answerVersionImpact } from "./version-impact.js";
import { evidenceCveIds } from "./evidence-identity.js";

export function sourceVersionChunks(proofs: readonly ProjectedEvidence[]): EvidenceChunk[] {
  return proofs.flatMap(proof => {
    if (proof.kind !== "source" || !proof.original_sha256 || !proof.parent_lineage_ids.length) return [];
    return (proof.version_facts ?? []).map(fact => {
      const text = (proof.source_cve_ids ?? []).join(", ") + "\n产品 " + fact.product + " 受影响版本规则（原始来源结构字段）：" + (fact.version_range.join(" OR ") || "未提供") + "。厂商身份未经本地核实。";
      return { ...proof.chunk, chunk_id: "chunk_version_" + sha256Json({ source: proof.chunk.chunk_id, fact }).slice(0,32), text,
        doc_type: "enrichment" as const, provenance: { ...proof.chunk.provenance, section: "raw:affected_versions" } };
    });
  });
}
export function sourceVersionImpact(items: readonly IntelItem[], proofs: readonly ProjectedEvidence[], query: VersionImpactQuery): VersionImpactAnswer {
  const admitted = new Map(items.map(item => [item.intel_id, item]));
  const candidates = proofs.flatMap(proof => {
    const original = admitted.get(proof.intel_id);
    if (!original || proof.kind !== "source" || !proof.original_sha256 || !proof.parent_lineage_ids.length) return [];
    return (proof.version_facts ?? []).map(fact => ({ ...original, cve_ids: [...(proof.source_cve_ids ?? [])],
      entities: { ...original.entities, product: fact.product, vendor: fact.vendor, version_range: fact.version_range } }));
  });
  // 不能回落到合并条目的 version_range：该范围可能属于另一个 CVE。
  return answerVersionImpact(candidates, query);
}
export function sourceScoreConflicts(proofs: readonly ProjectedEvidence[], chunks: readonly EvidenceChunk[]): SourceConflict[] {
  const cited = new Set(chunks.flatMap(chunk => evidenceCveIds(chunk.text)));
  const groups = new Map<string, Map<string, Set<number>>>();
  for (const proof of proofs) {
    if (proof.kind !== "source" || !proof.original_sha256 || !proof.parent_lineage_ids.length) continue;
    for (const fact of proof.score_facts ?? []) {
      if (!cited.has(fact.cve_id) || !(proof.source_cve_ids ?? []).includes(fact.cve_id)) continue;
      const sources = groups.get(fact.cve_id) ?? new Map<string, Set<number>>();
      const values = sources.get(fact.source) ?? new Set<number>(); values.add(fact.score);
      sources.set(fact.source, values); groups.set(fact.cve_id, sources);
    }
  }
  const conflicts: SourceConflict[] = [];
  for (const [cve, sources] of groups) {
    const values = [...sources].flatMap(([source, scores]) => [...scores].map(score => ({source: source as SourceConflict["values"][number]["source"], score})));
    if (values.length < 2 || new Set(values.map(v => v.score)).size < 2) continue;
    conflicts.push({ field: "cvss_v3_base", values, resolved: false,
      rationale: cve + " 的原始来源存在 CVSS v3.1 分歧；保留每源分值，未以单一结论覆盖。" });
  }
  return conflicts;
}
