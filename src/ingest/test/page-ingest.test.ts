import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, sha256 } from "@safetrace/shared";
import { extractAdvisoryWithFallback } from "../src/extraction-fallback.js";
import { ingestCollectedPage } from "../src/page-ingest.js";
import { buildSourceEvidenceChunks } from "../src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../../qa/src/q2-retrieval.js";
import type { PageFetchResult } from "../src/firecrawl.js";
import type { PageIngestOptions } from "../src/page-ingest.js";

async function setup(store = new MemoryEventStore()) {
  const bus = new EventBus({ store });
  const text = "CVE-2024-12345 affects the vendor product and administrators should install the fixed release.";
  const page: PageFetchResult = { source_url: "https://vendor.example/advisory", final_url: "https://vendor.example/advisory", title: "Vendor advisory", text, fetched_at: "2026-09-29T00:00:00.000Z", provider: "direct", content_sha256: sha256(text), fetched_via: "direct", stale: false, trace_id: "tr_web_ingest", lineage_ids: [], fallback_reasons: [] };
  const extraction = await extractAdvisoryWithFallback(page, { bus });
  const opts: PageIngestOptions = { enabled: true, source: { source_id: "registered_vendor", source_type: "vendor_advisory", url: page.source_url, status: "active", poll_interval_s: 3600, rate_per_min: 5, requires_api_key: false }, published_at: "2026-09-28T00:00:00.000Z", source_reliability: 0.9, bus, now: new Date("2026-09-30T00:00:00Z") };
  return { store, bus, page, extraction, opts };
}

test("SQLite webpage → DQ1 → source chunks → BM25 retains source and parent chain", async () => {
  const { page, extraction, opts, bus } = await setup();
  const admitted = await ingestCollectedPage(page, extraction, opts);
  assert.equal(admitted.status, "accepted");
  const mapping = { [admitted.item.intel_id]: admitted.lineage_id };
  const built = await buildSourceEvidenceChunks([admitted.item], [admitted.raw], [admitted.item], [admitted.verdict], mapping, { bus, trace_id: page.trace_id });
  assert.equal(built.chunks.length, 1);
  assert.equal(built.chunks[0]!.provenance.sha256, page.content_sha256);
  assert.equal(built.chunks[0]!.provenance.url, page.final_url);
  const index = new MemoryIndex({ bus });
  await indexChunks(index, built.chunks, { collection_name: "page_preview", model_id: index.modelId, dim: 256, metric: "cosine" }, { trace_id: page.trace_id, parent_lineage_ids: built.parent_lineage_ids });
  const retrieved = await index.search({ query_id: "q_page", query_text: "CVE-2024-12345", top_k: 1, trace_id: page.trace_id, schema_version: "1.0" });
  assert.equal(retrieved.chunks[0]?.chunk_id, built.chunks[0]!.chunk_id);
  const rows = await bus.readLineage(page.trace_id);
  const construction = rows.find(r => r.stage === "ingest.evidence_chunks")!;
  assert.ok(construction.parent_lineage_ids.includes(admitted.lineage_id));
  assert.ok(rows.find(r => r.stage === "q2.bm25_index")!.parent_lineage_ids.includes(construction.lineage_id));
  await assert.rejects(buildSourceEvidenceChunks([admitted.item], [admitted.raw], [admitted.item], [admitted.verdict], mapping), /snapshot reader/);
  const emptyBus = new EventBus({ store: new MemoryEventStore() });
  await assert.rejects(buildSourceEvidenceChunks([admitted.item], [admitted.raw], [admitted.item], [admitted.verdict], mapping, { bus: emptyBus, trace_id: page.trace_id }), /snapshot missing/);
  const wrong = { ...admitted.raw, url: "https://other.example/fake" };
  await assert.rejects(buildSourceEvidenceChunks([admitted.item], [wrong], [admitted.item], [admitted.verdict], mapping, { bus, trace_id: page.trace_id }), /source URL mismatch/);
  assert.ok((await bus.readLineage(page.trace_id)).some(r => r.stage === "ingest.evidence_chunks" && r.status === "failed"));
});

test("grounded registered webpage reaches DQ1 with separate publication/admission clocks", async () => {
  const { store, bus, page, extraction, opts } = await setup();
  const result = await ingestCollectedPage(page, extraction, opts);
  assert.equal(result.status, "accepted");
  assert.equal(result.item.published_at, opts.published_at);
  assert.equal(result.item.first_seen_at, opts.now!.toISOString());
  assert.equal(result.item.entities.product, null);
  assert.equal((await store.read("raw.docs")).length, 1);
  assert.equal((await store.read("dq.verdicts")).length, 1);
  const events = await store.read("intel.items");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.causation_id, (await store.read("dq.verdicts"))[0]!.event_id);
  assert.equal((await bus.getLastGoodPageSnapshotByHash(page.content_sha256))?.text, page.text);
  const rows = await bus.readLineage(page.trace_id);
  const stages = ["ingest.page_snapshot", "ingest.page_raw_publish", "ingest.page_construct", "ingest.page_dq1", "ingest.page_publish"];
  const chain = stages.map(stage => rows.find(r => r.stage === stage)!);
  assert.ok(chain.every(Boolean));
  for (let i = 1; i < chain.length; i++) assert.ok(chain[i]!.parent_lineage_ids.includes(chain[i - 1]!.lineage_id));
  assert.ok(!JSON.stringify(chain).includes(page.text));
});

test("disabled/stale/missing metadata/unsafe URLs and invented candidate fail before public events", async () => {
  for (const which of ["disabled", "stale", "missing_date", "wrong_source", "hash", "planned", "candidate_url", "candidate_text", "localhost", "secret", "review"] as const) {
    const { store, page, extraction, opts } = await setup();
    if (which === "disabled") opts.enabled = false;
    if (which === "stale") page.stale = true;
    if (which === "missing_date") opts.published_at = "";
    if (which === "wrong_source") opts.source.url = "https://other.example/advisory";
    if (which === "hash") page.content_sha256 = "0".repeat(64);
    if (which === "planned") opts.source.status = "planned";
    if (extraction.status === "candidate") {
      if (which === "candidate_url") extraction.candidate.source_url = "https://other.example/advisory";
      if (which === "candidate_text") extraction.candidate.summary = "invented claim";
    }
    if (which === "localhost" || which === "secret") {
      const url = which === "localhost" ? "https://localhost/advisory" : "https://vendor.example/advisory?api_key=do-not-log";
      opts.source.url = url; page.source_url = url; page.final_url = url;
    }
    const value = which === "review" ? { status: "needs_human_review" as const, reason: "pending", trace_id: page.trace_id, lineage_ids: extraction.lineage_ids } : extraction;
    assert.equal((await ingestCollectedPage(page, value, opts)).status, "rejected", which);
    assert.equal((await store.read("raw.docs")).length, 0);
    assert.equal((await store.read("intel.items")).length, 0);
    assert.ok(!JSON.stringify(await opts.bus.readLineage(page.trace_id)).includes("do-not-log"));
  }
});

test("DQ1 quarantine retains a verdict without publishing intel", async () => {
  const { store, page, extraction, opts } = await setup();
  opts.published_at = "2099-01-01T00:00:00Z";
  const result = await ingestCollectedPage(page, extraction, opts);
  assert.equal(result.status, "held");
  assert.equal(result.verdict.verdict, "quarantine");
  assert.equal((await store.read("dq.verdicts")).length, 1);
  assert.equal((await store.read("intel.items")).length, 0);
});

test("snapshot storage failure produces sanitized stage failure lineage", async () => {
  class BrokenStore extends MemoryEventStore {
    override async saveLastGoodPageSnapshot(): Promise<boolean> { throw new Error("private-storage-detail"); }
  }
  const { bus, page, extraction, opts } = await setup(new BrokenStore());
  await assert.rejects(ingestCollectedPage(page, extraction, opts));
  const records = await bus.readLineage(page.trace_id);
  assert.ok(records.some(r => r.stage === "ingest.page_snapshot" && r.status === "failed"));
  assert.ok(!JSON.stringify(records).includes("private-storage-detail"));
});
