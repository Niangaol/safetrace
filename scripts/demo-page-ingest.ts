import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, SqliteEventStore, nextId, sha256 } from "@safetrace/shared";
import { extractAdvisoryWithFallback } from "../src/ingest/src/extraction-fallback.js";
import { ingestCollectedPage } from "../src/ingest/src/page-ingest.js";
import { buildSourceEvidenceChunks } from "../src/ingest/src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../src/qa/src/q2-retrieval.js";
import type { PageFetchResult } from "../src/ingest/src/firecrawl.js";

// Synthetic vendor text, no fetch or model adapter. Not evidence of live crawling.
const path = resolve(process.env.SQLITE_PATH ?? "./var/page-ingest-demo.sqlite");
await mkdir(dirname(path), { recursive: true });
const now = new Date();
const trace = nextId("tr");
const text = "CVE-2024-12345 affects the demo product and administrators should install the fixed release.";
const page: PageFetchResult = { source_url: "https://vendor.example/demo", final_url: "https://vendor.example/demo", title: "Synthetic demo advisory", text, fetched_at: now.toISOString(), provider: "direct", content_sha256: sha256(text), trace_id: trace, lineage_ids: [], fetched_via: "direct", stale: false, fallback_reasons: [] };
const store = new SqliteEventStore(path);
try {
  const bus = new EventBus({ store });
  const extraction = await extractAdvisoryWithFallback(page, { bus });
  const options = { enabled: true, source: { source_id: "synthetic_demo_vendor", source_type: "vendor_advisory" as const, url: page.source_url, status: "active" as const, poll_interval_s: 3600, rate_per_min: 5, requires_api_key: false }, published_at: new Date(now.getTime() - 86400000).toISOString(), source_reliability: 0.9, bus, now };
  const admitted = await ingestCollectedPage(page, extraction, options);
  const rejected = await ingestCollectedPage({ ...page, stale: true }, extraction, options);
  assert.equal(admitted.status, "accepted");
  assert.equal(rejected.status, "rejected");
  const built = await buildSourceEvidenceChunks([admitted.item], [admitted.raw], [admitted.item], [admitted.verdict], { [admitted.item.intel_id]: admitted.lineage_id }, { bus, trace_id: trace });
  const index = new MemoryIndex({ bus });
  await indexChunks(index, built.chunks, { collection_name: "page_demo", model_id: index.modelId, dim: 256, metric: "cosine" }, { trace_id: trace, parent_lineage_ids: built.parent_lineage_ids });
  const retrieved = await index.search({ query_id: "demo_query", query_text: "CVE-2024-12345", top_k: 1, trace_id: trace, schema_version: "1.0" });
  assert.equal(retrieved.chunks.length, 1);
  assert.equal(retrieved.chunks[0]!.provenance.sha256, page.content_sha256);
  console.log(JSON.stringify({ source_chunks: built.chunks.length, retrieved_chunks: retrieved.chunks.length, index_mode: "transient_bm25_preview", source_hash_matches: true }));
  console.log(JSON.stringify({ mock: true, network_requests: 0, model_calls: 0, trace_id: trace, status: admitted.status, stale_case: rejected.status, sqlite_path: path }, null, 2));
} finally { store.close(); }
const reopened = new SqliteEventStore(path);
try {
  const rows = await reopened.readLineage(trace);
  assert.ok(rows.some(r => r.stage === "ingest.page_publish"));
  assert.equal((await reopened.getLastGoodPageSnapshotByHash(page.content_sha256))?.text, text);
  const count = (await reopened.read("intel.items", 0, 10000)).filter(e => e.trace_id === trace).length;
  assert.equal(count, 1);
  console.log(JSON.stringify({ restart_verified: true, admitted_events: count, lineage_records: rows.length }));
} finally { reopened.close(); }
