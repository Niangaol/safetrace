import { nowIso, sha256, sha256Json } from "@safetrace/shared";
import type { EventBus, IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import type { SourceEntry } from "./registry.js";
import { assertAllowedUrl } from "./firecrawl.js";
import type { PageFetchResult } from "./firecrawl.js";
import type { ExtractionResult } from "./extraction-fallback.js";
import { assessQualityVerdict } from "./dq1.js";

export interface PageIngestOptions {
  enabled: boolean;
  source: SourceEntry;
  published_at: string;
  source_reliability: number;
  bus: EventBus;
  now?: Date;
}
export type PageIngestResult = { status: "rejected"; reason: string } | {
  status: "accepted" | "held"; item: IntelItem; raw: RawDoc; verdict: QualityVerdict; lineage_id: string;
};

/** Explicit operator-supplied source metadata; never infer a publication date from fetch time. */
export async function ingestCollectedPage(page: PageFetchResult, extraction: ExtractionResult, opts: PageIngestOptions): Promise<PageIngestResult> {
  const bus = opts.bus;
  const reject = async (reason: string): Promise<PageIngestResult> => {
    await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: extraction.lineage_ids,
      stage: "ingest.page_gate", operation_version: "page-ingest.v1", status: "rejected",
      input_refs: [{ kind: "PageSnapshot", id: "url:" + sha256(page.source_url), sha256: page.content_sha256 }], decision: { reason } });
    return { status: "rejected", reason };
  };
  if (!opts.enabled) return reject("page ingestion is not explicitly enabled");
  if (page.stale) return reject("stale pages require manual review, not automatic ingestion");
  if (extraction.status !== "candidate") return reject("extraction requires human review");
  if (extraction.trace_id !== page.trace_id || !extraction.lineage_ids.length) return reject("page and extraction must have linked lineage");
  if (!opts.source.source_id.trim() || opts.source.status !== "active" || opts.source.source_type !== "vendor_advisory") return reject("explicit active vendor_advisory source registration required");
  if (opts.source.url !== page.source_url) return reject("registered source URL does not match fetched page");
  try {
    const host = new URL(opts.source.url).hostname;
    const source = assertAllowedUrl(opts.source.url, [host]); const final = assertAllowedUrl(page.final_url, [host]);
    if (source.protocol !== "https:" || final.protocol !== "https:" || source.host !== final.host || source.username || source.password || final.username || final.password) return reject("source and final URL must be same-host public HTTPS");
  } catch { return reject("invalid registered source URL"); }
  if (!opts.published_at || !/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(opts.published_at) || !Number.isFinite(Date.parse(opts.published_at))) return reject("explicit timezone-qualified publication timestamp required");
  if (!Number.isFinite(opts.source_reliability) || opts.source_reliability < 0 || opts.source_reliability > 1) return reject("explicit source reliability in [0,1] required");
  const c = extraction.candidate;
  const sourceUrl = new URL(page.source_url); sourceUrl.search = ""; sourceUrl.hash = "";
  if (c.source_url !== sourceUrl.toString()) return reject("candidate source URL does not match page");
  if (sha256(page.text) !== page.content_sha256) return reject("page SHA-256 mismatch");
  if (!c.title.trim() || c.title.length > 300 || (!page.text.includes(c.title) && page.title !== c.title) || !c.summary.trim() || c.summary.length > 1500 || !page.text.includes(c.summary)) return reject("candidate title and summary must be grounded in this page");
  if (!c.cve_ids.length || c.cve_ids.some(id => !/^CVE-\d{4}-\d{4,}$/.test(id) || !page.text.toUpperCase().includes(id)) || c.evidence_quotes.some(q => !q.trim() || !page.text.includes(q)) || !c.evidence_quotes.includes(c.summary) || !Number.isFinite(c.confidence) || c.confidence < 0.85 || c.confidence > 1) return reject("candidate identifiers, quotes or confidence failed evidence check");
  const snapshot = { source_url: page.source_url, final_url: page.final_url, title: page.title, text: page.text, fetched_at: page.fetched_at, provider: page.provider, content_sha256: page.content_sha256, lineage_ids: page.lineage_ids };
  let phase = "snapshot";
  let parents = [...extraction.lineage_ids];
  try {
    await bus.saveLastGoodPageSnapshot(snapshot);
    const saved = await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: parents,
      stage: "ingest.page_snapshot", operation_version: "page-ingest.v1", status: "success",
      input_refs: [{ kind: "PageSnapshot", id: "page:" + page.content_sha256, sha256: page.content_sha256 }],
      output_refs: [{ kind: "RawPageSnapshot", id: "sqlite-page:" + page.content_sha256, sha256: page.content_sha256 }] });
    parents = [saved.lineage_id];
    phase = "raw_publish";
    const raw: RawDoc = { source_id: opts.source.source_id, source_type: "vendor_advisory", external_id: page.content_sha256, url: page.final_url, fetched_at: page.fetched_at, content_type: "text", payload_ref: "sqlite-page:" + page.content_sha256 };
    const rawEnv = await bus.publish("raw.docs", raw, { trace_id: page.trace_id });
    const rawPublished = await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: parents, causation_id: rawEnv.event_id,
      stage: "ingest.page_raw_publish", operation_version: "page-ingest.v1", status: "success",
      input_refs: [{ kind: "RawPageSnapshot", id: raw.payload_ref, sha256: page.content_sha256 }],
      output_refs: [{ kind: "RawDoc", id: rawEnv.event_id, sha256: sha256Json(raw) }] });
    parents = [rawPublished.lineage_id];
    phase = "construct";
    const item: IntelItem = { intel_id: "intel_page_" + sha256Json({ source: opts.source.source_id, hash: page.content_sha256 }).slice(0, 32), cve_ids: [...new Set(c.cve_ids)], source_ids: [opts.source.source_id], title: c.title, summary: c.summary, published_at: opts.published_at, first_seen_at: opts.now?.toISOString() ?? nowIso(), entities: { product: null, vendor: null, version_range: [], cwe: [], cpes: [] }, raw_refs: [raw.payload_ref], source_reliability: opts.source_reliability, schema_version: "1.0" };
    const construction = await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: parents, causation_id: rawEnv.event_id,
      stage: "ingest.page_construct", operation_version: "page-ingest.v1", status: "success",
      input_refs: [{ kind: "PageSnapshot", id: raw.payload_ref, sha256: page.content_sha256 }, { kind: "AdvisoryCandidate", id: item.intel_id, sha256: sha256Json(c) }, { kind: "SourceMetadata", id: opts.source.source_id, sha256: sha256Json({ source: opts.source, published_at: opts.published_at, reliability: opts.source_reliability }) }],
      output_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }] });
    parents = [construction.lineage_id];
    phase = "dq1";
    const verdict = assessQualityVerdict(item, { now: opts.now });
    const dqEnv = await bus.publish("dq.verdicts", verdict, { trace_id: page.trace_id, causation_id: rawEnv.event_id });
    const accepted = verdict.verdict === "pass" || verdict.verdict === "degrade";
    const dq = await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: [construction.lineage_id], causation_id: dqEnv.event_id,
      stage: "ingest.page_dq1", operation_version: verdict.gate_version, status: accepted ? "success" : "review",
      input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }], output_refs: [{ kind: "QualityVerdict", id: item.intel_id, sha256: sha256Json(verdict) }], decision: { reason: verdict.verdict, quality_score: verdict.quality_score, review_required: !accepted } });
    parents = [dq.lineage_id];
    phase = "publish";
    if (accepted) {
      const intelEnv = await bus.publish("intel.items", item, { trace_id: page.trace_id, causation_id: dqEnv.event_id });
      await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: [dq.lineage_id], causation_id: intelEnv.event_id,
        stage: "ingest.page_publish", operation_version: "page-ingest.v1", status: "success", input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }], output_refs: [{ kind: "EventEnvelope", id: intelEnv.event_id, sha256: sha256Json(item) }] });
    }
    return { status: accepted ? "accepted" : "held", item, raw, verdict, lineage_id: dq.lineage_id };
  } catch (error) {
    await bus.recordLineage({ trace_id: page.trace_id, parent_lineage_ids: parents,
      stage: "ingest.page_" + phase, operation_version: "page-ingest.v1", status: "failed",
      input_refs: [{ kind: "PageSnapshot", id: "page:" + page.content_sha256, sha256: page.content_sha256 }],
      error: "page admission stage failed; raw details omitted" });
    throw error;
  }
}
