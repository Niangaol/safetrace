import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { EvidenceChunk } from "@safetrace/shared";
import { indexSourceChunks } from "../src/source-index.js";
import type { SourceIndexOptions } from "../src/source-index.js";

const chunks: EvidenceChunk[] = [{ chunk_id: "source_1", doc_type: "vuln_advisory", text: "CVE-2024-12345 vendor advisory", quality_score: 0.95, provenance: { url: "https://vendor.example/advisory", section: "parsed", sha256: "a".repeat(64) } }];
function options(): SourceIndexOptions {
  return { enabled: true, offline: false, url: "http://127.0.0.1:6333", collection: "source_collection", profile: { provider: "vllm", model_id: "bge-m3", model_version: "v1", dimension: 2 }, bus: new EventBus({ store: new MemoryEventStore() }), trace_id: "tr_source_index", parent_lineage_ids: ["ln_chunk_build"], embedder: async texts => ({ vectors: texts.map(() => [0.2, 0.8]), provider: "vllm", model_id: "bge-m3", model_version: "v1", degraded_to: "" }) };
}

test("source index is opt-in and rejects offline/fallback/cache before any service call", async () => {
  for (const patch of [{ enabled: false }, { offline: true }, { source_degraded_to: "fixture" }, { profile: { provider: "cache", model_id: "hash-256", model_version: "v0", dimension: 256 } }, { parent_lineage_ids: [] }]) {
    let calls = 0;
    const opts = { ...options(), ...patch, embedder: async () => { calls++; throw new Error("unexpected embedding"); }, fetch_impl: (async () => { calls++; throw new Error("unexpected Qdrant"); }) as typeof fetch };
    if (!opts.enabled) assert.equal((await indexSourceChunks(chunks, opts)).status, "disabled");
    else {
      await assert.rejects(indexSourceChunks(chunks, opts));
      assert.ok((await opts.bus.readLineage(opts.trace_id)).some(r => r.stage === "runner.source_index_gate" && r.status === "rejected"));
    }
    assert.equal(calls, 0);
  }
});

test("source index sends original vectors, source hash, version and audited gate to Qdrant", async () => {
  const requests: Array<{ url: string; body: any }> = [];
  const opts = options();
  opts.fetch_impl = (async (input, init) => {
    requests.push({ url: String(input), body: JSON.parse(String(init?.body)) });
    return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200 });
  }) as typeof fetch;
  assert.deepEqual(await indexSourceChunks(chunks, opts), { status: "indexed", chunks: 1 });
  assert.equal(requests.length, 2);
  assert.equal(requests[0]!.body.vectors.dense.distance, "Cosine");
  assert.deepEqual(requests[1]!.body.points[0].vector.dense, [0.2, 0.8]);
  assert.deepEqual(requests[1]!.body.points[0].payload.provenance, chunks[0]!.provenance);
  assert.equal(requests[1]!.body.points[0].payload.embedding_model_version, "v1");
  const rows = await opts.bus.readLineage(opts.trace_id);
  const gate = rows.find(r => r.stage === "runner.source_index_gate")!;
  const indexing = rows.find(r => r.stage === "q2.qdrant_index")!;
  assert.equal(indexing.status, "success");
  assert.ok(gate.parent_lineage_ids.includes("ln_chunk_build"));
  assert.ok(indexing.parent_lineage_ids.includes(gate.lineage_id));
});

test("runtime cache fallback and Qdrant failure never report indexed", async () => {
  let calls = 0;
  const opts = options();
  opts.embedder = async () => ({ vectors: [[0.2, 0.8]], provider: "cache", model_id: "bge-m3", model_version: "v1", degraded_to: "cache" });
  opts.fetch_impl = (async () => { calls++; return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200 }); }) as typeof fetch;
  await assert.rejects(indexSourceChunks(chunks, opts));
  assert.equal(calls, 0);
  const broken = options();
  broken.fetch_impl = (async () => new Response("down", { status: 503 })) as typeof fetch;
  await assert.rejects(indexSourceChunks(chunks, broken));
  assert.ok((await broken.bus.readLineage(broken.trace_id)).some(r => r.stage === "q2.qdrant_index" && r.status === "degraded"));
});
