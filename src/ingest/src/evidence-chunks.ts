import { nowIso, sha256Json } from "@safetrace/shared";
import type { EventBus, EvidenceChunk, IntelItem, QualityVerdict, RawDoc, SourceType } from "@safetrace/shared";
import { sha256PayloadRef } from "./common.js";

export interface SourceEvidenceChunkBuildResult {
  chunks: EvidenceChunk[];
  parent_lineage_ids: string[];
  skipped: Array<{ intel_id: string; reason: string }>;
}

/**
 * 信任级口径（C-02）：
 * - trusted = 结构化权威源 API 直读（NVD/KEV/CVE.org/OSV/GHSA/arXiv）或本系统由其派生；
 * - untrusted = 网页/文档类外部文本（厂商公告页、安全社区、博客、PoC）；
 * - standard_policy 属于文档类，按 untrusted 处理（标准正文仍是外部可控文本）。
 * 缺省（unknown）由调用方按最保守方式处理，禁止在缺失时猜测。
 */
function sourceTrust(sourceType: SourceType): EvidenceChunk["trust"] {
  switch (sourceType) {
    case "nvd_cve":
    case "cve_org":
    case "ghsa":
    case "osv":
    case "kev":
    case "paper":
      return "trusted";
    default:
      return "untrusted";
  }
}

function sourceDocType(sourceType: SourceType): EvidenceChunk["doc_type"] | undefined {
  switch (sourceType) {
    case "nvd_cve":
    case "cve_org":
    case "ghsa":
    case "osv":
    case "kev":
    case "poec_source":
      return "vuln_advisory";
    case "vendor_advisory":
    case "security_community":
    case "security_blog":
      return "vendor_advisory";
    case "standard_policy":
      return "policy";
    case "paper":
      return "paper";
    default:
      return undefined;
  }
}

function identityKeys(item: IntelItem): Set<string> {
  const ids = [
    ...item.cve_ids,
    ...(item.ghsa_ids ?? []),
    ...(item.osv_ids ?? []),
    ...(item.aliases ?? []),
  ].map((id) => id.trim().toUpperCase()).filter(Boolean);
  return new Set(ids.length ? ids : ["INTEL:" + item.intel_id]);
}

function renderParsedItem(item: IntelItem): string {
  return [
    item.title.trim(),
    item.summary?.trim() ?? "",
    item.cve_ids.length ? "CVE: " + item.cve_ids.join(", ") : "",
    item.entities.vendor ? "Vendor: " + item.entities.vendor : "",
    item.entities.product ? "Product: " + item.entities.product : "",
    item.entities.version_range.length ? "Affected versions: " + item.entities.version_range.join(", ") : "",
  ].filter(Boolean).join("\n");
}

/**
 * Build one source-faithful EvidenceChunk per pre-dedupe parsed item.
 * It never indexes merged multi-source text against a single source URL:
 * each chunk points to the exact RawDoc payload_ref used by that parser and
 * inherits eligibility/quality from its unique DQ1-accepted merged parent.
 */
async function buildChunks(
  parsed: IntelItem[],
  rawDocs: RawDoc[],
  merged: IntelItem[],
  verdicts: QualityVerdict[],
  lineageParentByIntelId: Record<string, string>,
  bus?: EventBus,
): Promise<SourceEvidenceChunkBuildResult> {
  const rawByRef = new Map(rawDocs.map((raw) => [raw.payload_ref, raw]));
  const verdictById = new Map(verdicts.map((verdict) => [verdict.item_id, verdict]));
  const chunks: EvidenceChunk[] = [];
  const parentIds = new Set<string>();
  const skipped: Array<{ intel_id: string; reason: string }> = [];

  for (const item of parsed) {
    if (item.raw_refs.length !== 1) {
      skipped.push({ intel_id: item.intel_id, reason: "parsed item must resolve to exactly one raw payload" });
      continue;
    }
    const raw = rawByRef.get(item.raw_refs[0]!);
    if (!raw) {
      skipped.push({ intel_id: item.intel_id, reason: "RawDoc payload_ref not present in this ingest run" });
      continue;
    }
    if (!item.source_ids.includes(raw.source_id)) {
      skipped.push({ intel_id: item.intel_id, reason: "RawDoc source_id does not match parsed item" });
      continue;
    }
    const docType = sourceDocType(raw.source_type);
    if (!docType) {
      skipped.push({ intel_id: item.intel_id, reason: "source_type has no EvidenceChunk doc_type mapping" });
      continue;
    }
    const itemKeys = identityKeys(item);
    const parents = merged.filter((candidate) => {
      const sameSource = item.source_ids.some((sourceId) => candidate.source_ids.includes(sourceId));
      const sameIdentity = [...itemKeys].some((id) => identityKeys(candidate).has(id));
      return sameSource && sameIdentity && candidate.raw_refs.includes(raw.payload_ref);
    });
    if (parents.length !== 1) {
      skipped.push({ intel_id: item.intel_id, reason: parents.length ? "DQ1 parent mapping is ambiguous" : "no merged DQ1 parent found" });
      continue;
    }
    const parent = parents[0]!;
    const verdict = verdictById.get(parent.intel_id);
    if (!verdict || (verdict.verdict !== "pass" && verdict.verdict !== "degrade")) {
      skipped.push({ intel_id: item.intel_id, reason: "merged DQ1 parent is not pass/degrade" });
      continue;
    }
    const dqLineageId = lineageParentByIntelId[parent.intel_id];
    if (!dqLineageId) {
      skipped.push({ intel_id: item.intel_id, reason: "DQ1 lineage parent missing" });
      continue;
    }
    const text = renderParsedItem(item);
    if (!text.trim()) {
      skipped.push({ intel_id: item.intel_id, reason: "parsed item has no indexable title/summary" });
      continue;
    }
    let payloadSha256: string;
    if (raw.payload_ref.startsWith("sqlite-page:")) {
      const hash = raw.payload_ref.slice("sqlite-page:".length);
      if (!/^[a-f0-9]{64}$/.test(hash) || !bus) throw new Error("SQLite page reference requires a valid SHA-256 and EventBus snapshot reader");
      const page = await bus.getLastGoodPageSnapshotByHash(hash);
      if (!page || page.content_sha256 !== hash || raw.url !== page.final_url) throw new Error("SQLite page snapshot missing or source URL mismatch");
      if ((!page.text.includes(item.title) && page.title !== item.title) || (item.summary && !page.text.includes(item.summary)) || item.cve_ids.some(id => !page.text.toUpperCase().includes(id.toUpperCase()))) throw new Error("SQLite page evidence is not grounded in saved source text");
      payloadSha256 = hash;
    } else {
      payloadSha256 = await sha256PayloadRef(raw.payload_ref);
    }
    const chunkId = "chunk_" + sha256Json({ raw_ref: raw.payload_ref, intel_id: item.intel_id, payload_sha256: payloadSha256 }).slice(0, 40);
    chunks.push({
      chunk_id: chunkId,
      doc_type: docType,
      text,
      quality_score: verdict.quality_score,
      // 上游发布时间只取自解析后的 IntelItem.published_at（适配器已归一化并登记 warning）；
      // 缺失即未知，不用抓取时间或当前时间顶替。
      ...(item.published_at ? { published_at: item.published_at } : {}),
      trust: sourceTrust(raw.source_type),
      provenance: { url: raw.url, section: "parsed:title+summary+entities", sha256: payloadSha256 },
    });
    parentIds.add(dqLineageId);
  }
  return { chunks, parent_lineage_ids: [...parentIds], skipped };
}

/** Audited boundary: no source text is duplicated in lineage. */
export async function buildSourceEvidenceChunks(
  parsed: IntelItem[], rawDocs: RawDoc[], merged: IntelItem[],
  verdicts: QualityVerdict[], lineageParentByIntelId: Record<string, string>,
  audit?: { bus: EventBus; trace_id: string },
): Promise<SourceEvidenceChunkBuildResult> {
  const startedAt = nowIso();
  const inputRefs = [
    ...parsed.map(item => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
    ...rawDocs.map(raw => ({ kind: "RawDoc", id: raw.payload_ref, sha256: sha256Json(raw) })),
    ...verdicts.map(verdict => ({ kind: "QualityVerdict", id: verdict.item_id, sha256: sha256Json(verdict) })),
  ];
  let built: SourceEvidenceChunkBuildResult;
  try {
    built = await buildChunks(parsed, rawDocs, merged, verdicts, lineageParentByIntelId, audit?.bus);
  } catch (error) {
    await audit?.bus.recordLineage({
      trace_id: audit.trace_id, stage: "ingest.evidence_chunks", operation_version: "source-chunks.v1",
      status: "failed", started_at: startedAt,
      parent_lineage_ids: [...new Set(Object.values(lineageParentByIntelId))],
      input_refs: inputRefs, error: "source chunk construction failed; raw payload unavailable or invalid",
    });
    throw error;
  }
  const record = await audit?.bus.recordLineage({
    trace_id: audit.trace_id, stage: "ingest.evidence_chunks", operation_version: "source-chunks.v1",
    status: built.skipped.length ? "degraded" : "success", started_at: startedAt,
    parent_lineage_ids: [...new Set(Object.values(lineageParentByIntelId))],
    input_refs: inputRefs,
    output_refs: built.chunks.map(chunk => ({ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
    decision: { reason: built.skipped.length ? JSON.stringify(built.skipped) : "source-faithful chunks built after DQ1" },
  });
  return record ? { ...built, parent_lineage_ids: [record.lineage_id] } : built;
}
