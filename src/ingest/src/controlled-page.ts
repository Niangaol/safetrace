import { sha256, sha256Json } from "@safetrace/shared";
import type { EventBus } from "@safetrace/shared";
import { assertAllowedUrl, fetchPageWithFallback } from "./firecrawl.js";
import type { ControlledFetchOptions } from "./firecrawl.js";
import { extractAdvisoryWithFallback } from "./extraction-fallback.js";
import { ingestCollectedPage } from "./page-ingest.js";
import { buildSourceEvidenceChunks } from "./evidence-chunks.js";
import type { SourceEntry } from "./registry.js";

export interface PageIngestMetadata { source: SourceEntry; published_at: string; source_reliability: number }
function object(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
export function parsePageIngestMetadata(value: unknown, url: string): PageIngestMetadata {
  if (!object(value) || !object(value.source)) throw new Error("explicit source metadata object required");
  const s = value.source;
  if (typeof s.source_id !== "string" || !/^[a-zA-Z0-9_-]+$/.test(s.source_id) || s.source_type !== "vendor_advisory" || s.status !== "active" || s.url !== url) throw new Error("active vendor source with matching URL required");
  assertAllowedUrl(url, [new URL(url).hostname]);
  if (typeof s.poll_interval_s !== "number" || s.poll_interval_s <= 0 || typeof s.rate_per_min !== "number" || s.rate_per_min <= 0 || typeof s.requires_api_key !== "boolean") throw new Error("source rate/poll/key declarations required");
  if (typeof value.published_at !== "string" || !/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value.published_at) || !Number.isFinite(Date.parse(value.published_at))) throw new Error("explicit publication date with timezone required");
  if (typeof value.source_reliability !== "number" || !Number.isFinite(value.source_reliability) || value.source_reliability < 0 || value.source_reliability > 1) throw new Error("explicit source reliability in [0,1] required");
  return { source: { source_id: s.source_id, source_type: "vendor_advisory", url, status: "active", poll_interval_s: s.poll_interval_s, rate_per_min: s.rate_per_min, requires_api_key: s.requires_api_key }, published_at: value.published_at, source_reliability: value.source_reliability };
}

/** Rules-only production entry: no cloud LLM adapter is wired before A-03/A-04 sign-off. */
export async function runControlledPage(url: string, opts: ControlledFetchOptions & { bus: EventBus; trace_id: string; ingest_enabled?: boolean; metadata?: unknown }) {
  let metadata: PageIngestMetadata | undefined;
  let parents = opts.parent_lineage_ids ?? [];
  if (opts.ingest_enabled === true) {
    try { metadata = parsePageIngestMetadata(opts.metadata, url); }
    catch {
      await opts.bus.recordLineage({ trace_id: opts.trace_id, parent_lineage_ids: parents, stage: "crawler.page_metadata", operation_version: "controlled-page.v1", status: "rejected",
        input_refs: [{ kind: "RequestedUrl", id: "url:" + sha256(url), sha256: sha256(url) }, { kind: "Metadata", id: "page-ingest-metadata", sha256: sha256Json(opts.metadata ?? null) }], decision: { reason: "metadata invalid; no network access attempted" } });
      throw new Error("page ingestion metadata invalid; no network access attempted");
    }
    const record = await opts.bus.recordLineage({ trace_id: opts.trace_id, parent_lineage_ids: parents, stage: "crawler.page_metadata", operation_version: "controlled-page.v1", status: "success",
      input_refs: [{ kind: "Metadata", id: metadata.source.source_id, sha256: sha256Json(metadata) }], output_refs: [{ kind: "ValidatedMetadata", id: metadata.source.source_id, sha256: sha256Json(metadata) }] });
    parents = [record.lineage_id];
  }
  const page = await fetchPageWithFallback(url, { ...opts, parent_lineage_ids: parents });
  const extraction = await extractAdvisoryWithFallback(page, { bus: opts.bus, trace_id: opts.trace_id, parent_lineage_ids: page.lineage_ids });
  if (!metadata) return { page, extraction };
  const admission = await ingestCollectedPage(page, extraction, { enabled: true, ...metadata, bus: opts.bus });
  if (admission.status !== "accepted") return { page, extraction, admission };
  const evidence = await buildSourceEvidenceChunks([admission.item], [admission.raw], [admission.item], [admission.verdict], { [admission.item.intel_id]: admission.lineage_id }, { bus: opts.bus, trace_id: opts.trace_id });
  return { page, extraction, admission, evidence };
}
