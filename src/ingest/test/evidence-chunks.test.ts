import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { runIngestOnce } from "../src/pipeline.js";
import { buildSourceEvidenceChunks } from "../src/evidence-chunks.js";
import { sha256PayloadRef } from "../src/common.js";
import { MemoryIndex, indexChunks } from "../../qa/src/q2-retrieval.js";

test("DQ1 → chunk construction → BM25 retrieval keeps audit parents", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const r = await runIngestOnce({ store, offline: true });
  const built = await buildSourceEvidenceChunks(r.parsed, r.fetched, r.merged, r.verdicts, r.lineage_parent_by_intel_id, { bus, trace_id: r.trace_id });
  const index = new MemoryIndex({ bus });
  await indexChunks(index, built.chunks, { collection_name: "source_test", model_id: index.modelId, dim: 256, metric: "cosine" }, { trace_id: r.trace_id, parent_lineage_ids: built.parent_lineage_ids });
  const found = await index.search({ query_id: "q_source", query_text: "CVE-2021-44228", top_k: 4, trace_id: r.trace_id, schema_version: "1.0" });
  assert.ok(found.chunks.length > 0);
  assert.ok(found.chunks.every(c => built.chunks.some(b => b.chunk_id === c.chunk_id)));
  const rows = await bus.readLineage(r.trace_id);
  const conversion = rows.find(row => row.stage === "ingest.evidence_chunks")!;
  assert.ok(conversion.parent_lineage_ids.includes(r.lineage_parent_by_intel_id[r.merged[0]!.intel_id]!));
  const indexing = rows.find(row => row.stage === "q2.bm25_index")!;
  assert.ok(indexing.parent_lineage_ids.includes(conversion.lineage_id));
  assert.ok(!JSON.stringify(conversion).includes(r.parsed[0]!.title));
});

async function sample() {
  return runIngestOnce({ store: new MemoryEventStore(), offline: true });
}

test("source chunks keep each parser text and exact RawDoc provenance, not merged text", async () => {
  const r = await sample();
  const built = await buildSourceEvidenceChunks(r.parsed, r.fetched, r.merged, r.verdicts, r.lineage_parent_by_intel_id);
  assert.equal(built.chunks.length, 4);
  assert.deepEqual(built.skipped, []);
  assert.equal(new Set(built.chunks.map(c => c.chunk_id)).size, 4);
  for (const [i, chunk] of built.chunks.entries()) {
    const parsed = r.parsed[i]!;
    const raw = r.fetched.find(d => d.payload_ref === parsed.raw_refs[0])!;
    assert.equal(chunk.provenance.url, raw.url);
    assert.equal(chunk.provenance.sha256, await sha256PayloadRef(raw.payload_ref));
    assert.ok(chunk.text.startsWith(parsed.title));
    if (parsed.summary) assert.ok(chunk.text.includes(parsed.summary));
  }
  assert.deepEqual(built.parent_lineage_ids, [r.lineage_parent_by_intel_id[r.merged[0]!.intel_id]]);
  const again = await buildSourceEvidenceChunks(r.parsed, r.fetched, r.merged, r.verdicts, r.lineage_parent_by_intel_id);
  assert.deepEqual(again.chunks, built.chunks);
});

test("review/quarantine and missing DQ lineage cannot become source evidence", async () => {
  const r = await sample();
  for (const verdict of ["review", "quarantine"] as const) {
    const out = await buildSourceEvidenceChunks(r.parsed, r.fetched, r.merged, r.verdicts.map(v => ({ ...v, verdict })), r.lineage_parent_by_intel_id);
    assert.equal(out.chunks.length, 0);
    assert.equal(out.skipped.length, 4);
  }
  const out = await buildSourceEvidenceChunks(r.parsed, r.fetched, r.merged, r.verdicts, {});
  assert.equal(out.chunks.length, 0);
});

test("ambiguous parent, missing raw or wrong source mapping fails closed", async () => {
  const r = await sample();
  const ambiguous = await buildSourceEvidenceChunks(r.parsed, r.fetched, [...r.merged, { ...r.merged[0]!, intel_id: "duplicate" }], r.verdicts, r.lineage_parent_by_intel_id);
  assert.equal(ambiguous.chunks.length, 0);
  const missing = await buildSourceEvidenceChunks(r.parsed, [], r.merged, r.verdicts, r.lineage_parent_by_intel_id);
  assert.equal(missing.chunks.length, 0);
  const wrong = await buildSourceEvidenceChunks(r.parsed, r.fetched.map(d => ({ ...d, source_id: "unrelated" })), r.merged, r.verdicts, r.lineage_parent_by_intel_id);
  assert.equal(wrong.chunks.length, 0);
  assert.ok(wrong.skipped.every(s => s.reason.includes("source_id")));
});
