import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, MemoryEventStore, sha256 } from "@safetrace/shared";
import type { IntelItem, EvidenceChunk } from "@safetrace/shared";
import { latestIntelSnapshot, desiredPayload, planIntelSync } from "../src/intel-index-plan.js";
import type { IntelIndexEvent, IndexPoint } from "../src/intel-index-plan.js";
import { cleanupIntelRun, syncIntelIndex } from "../src/intel-index-sync.js";
import { qdrantPointId } from "../src/q2-retrieval.js";
import { indexSourceChunks } from "../src/source-index.js";
import { acquireIntelIndexLease } from "../../../scripts/intel-index-lock.js";
import { ingestCollectedPage } from "../../ingest/src/page-ingest.js";
import { extractAdvisoryWithFallback } from "../../ingest/src/extraction-fallback.js";
import type { PageFetchResult } from "../../ingest/src/firecrawl.js";

const base = JSON.parse(readFileSync("fixtures/intelitem.sample.json", "utf8")) as IntelItem;
const model = { model_id: "bge-m3", model_version: "v1" };
function events(key: string, start: number, released = true): IntelIndexEvent[] {
  return [{ seq: start, event_id: "ev_i" + start, trace_id: "tr", causation_id: null, topic: "intel.items", payload: { ...base, intel_id: key, source_ids: ["nvd_cve"] } },
    { seq: start + 1, event_id: "ev_q" + start, trace_id: "tr", causation_id: "ev_i" + start, topic: "dq.verdicts", payload: { item_id: key, item_kind: "intel", verdict: released ? "pass" : "quarantine", quality_score: 0.95,
      dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], gate_version: "1.0.1" } }];
}
function adapters(state: Map<number | string, IndexPoint>, runId = "run_a") {
  return { write: async (chunks: EvidenceChunk[], mark: () => void) => { mark(); for (const c of chunks) state.set(qdrantPointId(c.chunk_id), { id: qdrantPointId(c.chunk_id), payload: { ...desiredPayload(c, model), index_run_id: runId } }); },
    revoke: async (ids: readonly (number | string)[]) => { for (const id of ids) state.delete(id); },
    cleanup: async (ids: readonly string[]) => { for (const [key, p] of state) if (p.payload.index_run_id === runId && ids.includes(String(p.payload.chunk_id))) state.delete(key); } };
}

test("retry/limit never deletes an accepted sole noncanonical copy outside the write selection", async () => {
  const snapshot = latestIntelSnapshot([...events("intel_a",1), ...events("intel_b",3)]);
  const desired = planIntelSync(snapshot, [], model).upsert;
  for (const selector of [{ retryIds: ["intel_a"] }, { limit: 1 }]) {
    const b = desired.find(c => c.chunk_id === "intel_b")!;
    const state = new Map<number | string, IndexPoint>([["old_uuid", { id: "old_uuid", payload: desiredPayload(b, model) }]]);
    await syncIntelIndex({ snapshot, points: [...state.values()], model, apply: true, ...selector, ...adapters(state), readSnapshot: () => snapshot });
    assert.equal(state.has("old_uuid"), true); assert.equal(state.has(qdrantPointId("intel_a")), true);
  }
  const b = desired.find(c => c.chunk_id === "intel_b")!;
  const state = new Map<number | string, IndexPoint>([["old_uuid", { id: "old_uuid", payload: desiredPayload(b, model) }]]);
  await syncIntelIndex({ snapshot, points: [...state.values()], model, apply: true, ...adapters(state), readSnapshot: () => snapshot });
  assert.equal(state.has("old_uuid"), false); assert.equal(state.has(qdrantPointId("intel_b")), true);
});

test("embedding failure before PUT preserves the existing valid point", async () => {
  const snapshot = latestIntelSnapshot(events("intel_a",1)); const chunk = planIntelSync(snapshot, [], model).upsert[0]!;
  const state = new Map<number | string, IndexPoint>([[qdrantPointId(chunk.chunk_id), { id: qdrantPointId(chunk.chunk_id), payload: desiredPayload(chunk, model) }]]);
  const before = structuredClone([...state.values()]);
  await assert.rejects(syncIntelIndex({ snapshot, points: [...state.values()], model, apply: true, retryIds: ["intel_a"], ...adapters(state),
    readSnapshot: () => snapshot, write: async () => { throw new Error("embed unavailable before PUT"); } }), /embed unavailable/);
  assert.deepEqual([...state.values()], before);
});

test("blocked quarantine retry still revokes existing point, never calls write, and exits failed", async () => {
  const snapshot = latestIntelSnapshot(events("intel_a",1,false)); let writes = 0;
  const state = new Map<number | string, IndexPoint>([[qdrantPointId("intel_a"), { id: qdrantPointId("intel_a"), payload: { chunk_id: "intel_a" } }]]);
  await assert.rejects(syncIntelIndex({ snapshot, points: [...state.values()], model, apply: true, retryIds: ["intel_a"], ...adapters(state),
    readSnapshot: () => snapshot, write: async () => { writes++; } }), /not released/);
  assert.equal(writes,0); assert.equal(state.size,0);
});

test("failed writer conditional cleanup cannot erase a newer writer replacement", async () => {
  const snapshot = latestIntelSnapshot(events("intel_a",1)); const chunk = planIntelSync(snapshot, [], model).upsert[0]!;
  const state = new Map<number | string, IndexPoint>();
  await assert.rejects(syncIntelIndex({ snapshot, points: [], model, apply: true, ...adapters(state,"run_a"), readSnapshot: () => snapshot,
    write: async (_chunks, mark) => { mark(); state.set(qdrantPointId(chunk.chunk_id), { id: qdrantPointId(chunk.chunk_id), payload: { ...desiredPayload(chunk,model), index_run_id: "run_b" } }); throw new Error("A uncertain PUT, B has already replaced it"); } }), /uncertain PUT/);
  assert.equal(state.get(qdrantPointId(chunk.chunk_id))!.payload.index_run_id,"run_b");
});

test("conditional Qdrant cleanup includes run ownership and chunk filter", async () => {
  let body: any;
  await cleanupIntelRun(["intel_a"], "run_a", { url: "http://127.0.0.1:1", collection: "test", fetchImpl: (async (_url,init) => {
    body = JSON.parse(String(init?.body)); return Response.json({ result: { status: "completed" } });
  }) as typeof fetch });
  assert.deepEqual(body.filter.must, [{ key: "index_run_id", match: { value: "run_a" } }, { key: "chunk_id", match: { any: ["intel_a"] } }]);
  assert.equal("points" in body,false);
});

test("collection lease rejects second writer and permits it only after owner release", () => {
  const dir = mkdtempSync(join(tmpdir(), "safetrace-lease-"));
  try {
    const release = acquireIntelIndexLease("http://127.0.0.1:6333/", "test", dir);
    try { assert.throws(() => acquireIntelIndexLease("http://127.0.0.1:6333", "test", dir), /already leased/); }
    finally { release(); }
    const again = acquireIntelIndexLease("http://127.0.0.1:6333", "test", dir); again(); again();
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test("actual page admission DQ→intel causality indexes exact source URL and cannot reuse an old DQ", async () => {
  const store = new MemoryEventStore(); const bus = new EventBus({ store });
  const text = "CVE-2024-12345 affects the vendor product and administrators should install the fixed release.";
  const page: PageFetchResult = { source_url: "https://vendor.example/advisory", final_url: "https://vendor.example/advisory", title: "Vendor advisory", text, fetched_at: "2026-09-29T00:00:00.000Z", provider: "direct", content_sha256: sha256(text), fetched_via: "direct", stale: false, trace_id: "tr_page", lineage_ids: [], fallback_reasons: [] };
  const extraction = await extractAdvisoryWithFallback(page,{bus});
  const admitted = await ingestCollectedPage(page, extraction, { enabled:true, bus, now:new Date("2026-09-30T00:00:00Z"), published_at:"2026-09-28T00:00:00Z", source_reliability:0.9,
    source:{source_id:"registered_vendor",source_type:"vendor_advisory",url:page.source_url,status:"active",poll_interval_s:3600,rate_per_min:5,requires_api_key:false} });
  assert.equal(admitted.status,"accepted");
  const rows: IntelIndexEvent[] = [];
  // Memory store publishes raw then DQ then intel; reconstruct their durable ordering.
  let seq=0;
  for(const topic of ["raw.docs","dq.verdicts","intel.items"] as const) for(const e of await store.read(topic)) rows.push({...e,topic,seq:++seq});
  const snapshot = latestIntelSnapshot(rows); assert.equal(snapshot.accepted.size,1);
  const plan = planIntelSync(snapshot,[],model); assert.equal(plan.upsert.length,1); assert.equal(plan.upsert[0]!.provenance.url,page.final_url);
  const it = rows.find(e=>e.topic==="intel.items")!;
  const reused = {...it,seq:4,event_id:"ev_reused",payload:{...it.payload as object,title:"new unreviewed title"}};
  assert.equal(latestIntelSnapshot([...rows,reused]).accepted.size,0);
  const lateQuarantine = {...rows.find(e=>e.topic==="dq.verdicts")!,seq:5,event_id:"ev_blocked",payload:{...rows.find(e=>e.topic==="dq.verdicts")!.payload as object,verdict:"quarantine"}};
  assert.equal(latestIntelSnapshot([...rows,lateQuarantine]).accepted.size,0);
});

test("actual source-index rejects acknowledged/malformed PUT and marks only points write attempts", async () => {
  const snapshot = latestIntelSnapshot(events("intel_a",1)); const chunks = planIntelSync(snapshot,[],model).upsert;
  for (const response of [{result:{status:"acknowledged"}}, {}, {result:{status:"completed"}}]) {
    let marks=0; const writes:any[]=[];
    const opts = { enabled:true,offline:false,url:"http://127.0.0.1:1",collection:"test",profile:{...model,provider:"local",dimension:2},bus:new EventBus({store:new MemoryEventStore()}),trace_id:"tr",parent_lineage_ids:["ln"],write_token:"run_owner",before_vector_write:()=>{marks++;},
      embedder:async (texts:string[])=>({vectors:texts.map(()=>[1,0]),...model,provider:"local",degraded_to:""}),
      fetch_impl:(async (_url,init)=>{const body=JSON.parse(String(init?.body));if(body.points){writes.push(body);return Response.json(response);}return Response.json(true);}) as typeof fetch };
    if((response as {result?:{status:string}}).result?.status==="completed") await indexSourceChunks(chunks,opts);
    else await assert.rejects(indexSourceChunks(chunks,opts),/confirm completed/);
    assert.equal(marks,1); assert.equal(writes[0].points[0].payload.index_run_id,"run_owner");
  }
  let marks=0;
  await assert.rejects(indexSourceChunks(chunks,{enabled:true,offline:false,url:"http://127.0.0.1:1",collection:"test",profile:{...model,provider:"local",dimension:2},bus:new EventBus({store:new MemoryEventStore()}),trace_id:"tr",parent_lineage_ids:["ln"],before_vector_write:()=>{marks++;},embedder:async()=>{throw new Error("embedding failed");}}),/embedding failed/);
  assert.equal(marks,0);
});
