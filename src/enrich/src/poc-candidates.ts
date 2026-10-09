/**
 * PoC 候选提取（F3 前半段）：只从**已验证原文**里显式标注 Exploit/PoC 的引用中
 * 提取候选元数据。纪律：
 *   - 不发起任何网络请求、不抓取链接内容、不下载或执行利用代码；
 *   - 引用存在 != 链接可达 != PoC 可用；本模块只产"候选来源记录"；
 *   - KEV 在野利用标记、模型判定、搜索引擎结论都**不是** PoC 可用性证明；
 *   - 每条候选绑定自己的 raw_ref/来源哈希/血缘，缺一即拒。
 */
import { sha256Json } from "@safetrace/shared";

export type PocCandidateSourceKind = "reference_tag_exploit" | "reference_tag_poc";
export interface PocCandidate {
  candidate_id: string;
  cve_id: string;
  source_id: string;
  raw_ref: string;
  source_url: string;
  source_sha256: string;
  reference_url: string;
  reference_tags: string[];
  evidence_kind: PocCandidateSourceKind;
  parent_lineage_ids: string[];
  note: string;
}

export interface PocCandidateInput {
  intel_id: string;
  cve_ids: readonly string[];
  item: { title: string; summary?: string; entities: { product: string | null; vendor: string | null } };
  raw: {
    payload_ref: string;
    source_id: string;
    url: string;
    source_type: string;
  };
  payload_bytes: Uint8Array;
  payload_sha256: string;
  parent_lineage_ids: readonly string[];
}

/** 引用标签里唯一被接受为 PoC 线索的词（大小写不敏感，整词匹配）。 */
const POC_TAGS = new Set(["exploit", "poc", "proof-of-concept", "proof of concept"]);
const MAX_REFERENCES = 50;

function isPublicHttps(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch { return false }
}

/** 从 NVD/CVE.org 两种原文形态里取 references；缺字段/畸形一律跳过，不猜。 */
export function extractExploitReferences(bytes: Uint8Array): { url: string; tags: string[] }[] {
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { return [] }
  const out: { url: string; tags: string[] }[] = [];
  const visit = (value: unknown): void => {
    if (!value || typeof value !== "object") return;
    const record = value as Record<string, unknown>;
    const url = record.url;
    const tags = record.tags;
    if (typeof url === "string" && Array.isArray(tags)) {
      const clean = tags.filter((t): t is string => typeof t === "string").map(t => t.trim().toLowerCase());
      out.push({ url, tags: clean });
      return;
    }
    for (const nested of Object.values(record)) {
      if (Array.isArray(nested)) { for (const item of nested) visit(item); continue }
      if (nested && typeof nested === "object") visit(nested);
    }
  };
  visit(parsed);
  return out;
}

/** 提取 PoC 候选：标签命中 + https 明文 URL + 归属 CVE 明确；否则不产候选。 */
export function extractPocCandidates(input: PocCandidateInput): PocCandidate[] {
  if (!input.payload_bytes.length || !/^[a-f0-9]{64}$/.test(input.payload_sha256)) return [];
  if (!input.parent_lineage_ids.length || input.parent_lineage_ids.some(id => typeof id !== "string" || !id)) return [];
  const references = extractExploitReferences(input.payload_bytes).slice(0, MAX_REFERENCES);
  const candidates: PocCandidate[] = [];
  for (const cveId of input.cve_ids) {
    for (const reference of references) {
      const tags = reference.tags.filter(tag => POC_TAGS.has(tag));
      if (tags.length === 0) continue;
      if (!isPublicHttps(reference.url)) continue;
      const evidence_kind: PocCandidateSourceKind = tags.includes("poc") || tags.some(t => t.includes("proof")) ? "reference_tag_poc" : "reference_tag_exploit";
      const candidate: PocCandidate = {
        candidate_id: "poc_" + sha256Json({ intel_id: input.intel_id, cve_id: cveId, reference_url: reference.url, source_id: input.raw.source_id }).slice(0, 32),
        cve_id: cveId,
        source_id: input.raw.source_id,
        raw_ref: input.raw.payload_ref,
        source_url: input.raw.url,
        source_sha256: input.payload_sha256,
        reference_url: reference.url,
        reference_tags: [...new Set(tags)].sort(),
        evidence_kind,
        parent_lineage_ids: [...input.parent_lineage_ids].sort(),
        note: "Reference tagged as exploit/PoC in the captured advisory; reachability and exploitability are NOT verified. No content was fetched and nothing was executed.",
      };
      if (candidates.some(c => c.candidate_id === candidate.candidate_id)) continue;
      candidates.push(candidate);
    }
  }
  return candidates.sort((a, b) => a.candidate_id.localeCompare(b.candidate_id));
}
