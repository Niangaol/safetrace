import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { IntelItem, QualityVerdict } from "@safetrace/shared";
import { latestIntelSnapshot, intelSummaryChunk, planIntelSync, desiredPayload } from "../src/intel-index-plan.js";
import type { IntelIndexEvent, IndexPoint } from "../src/intel-index-plan.js";
import { qdrantPointId } from "../src/q2-retrieval.js";
import { readIntelPoints, revokeIntelPoints, syncIntelIndex } from "../src/intel-index-sync.js";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";

const sample = JSON.parse(readFileSync("fixtures/intelitem.sample.json", "utf8")) as IntelItem;
const model = { model_id: "bge-m3", model_version: "test-v1" };
function item(seq: number, key = "intel_test", title = "original"): IntelIndexEvent {
  return { seq, event_id: "ev_i" + seq, trace_id: "tr_test", causation_id: null, topic: "intel.items", payload: { ...sample, intel_id: key, title, source_ids: ["nvd_cve"] } };
}
function dq(seq: number, it: IntelIndexEvent, verdict = "pass"): IntelIndexEvent {
  return { seq, event_id: "ev_q" + seq, trace_id: "tr_test", causation_id: it.event_id, topic: "dq.verdicts", payload: { item_id: (it.payload as IntelItem).intel_id, item_kind: "intel", quality_score: 0.95, verdict,
      dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], gate_version: "1.0.1" } };
}
function point(events: IntelIndexEvent[]): IndexPoint {
  const entry = [...latestIntelSnapshot(events).accepted.values()][0]!;
  const chunk = intelSummaryChunk(entry);
  return { id: qdrantPointId(chunk.chunk_id), payload: desiredPayload(chunk, model) };
}
test("index release uses latest seq and DQ event binding, not historical passes or array order", () => {
  const old = item(1), oldDq = dq(2, old), fresh = item(3, "intel_test", "new");
  assert.equal(latestIntelSnapshot([oldDq, fresh, old]).accepted.size, 0);
  const currentDq = dq(4, fresh);
  assert.equal([...latestIntelSnapshot([currentDq, oldDq, fresh, old]).accepted.values()][0]!.item.title, "new");
  assert.equal(latestIntelSnapshot([old, oldDq, dq(5, old, "quarantine")]).accepted.size, 0);
  assert.equal(latestIntelSnapshot([old, { ...oldDq, causation_id: "wrong" }]).accepted.size, 0);
  assert.equal(latestIntelSnapshot([old]).accepted.size, 0);
  assert.throws(() => latestIntelSnapshot([old, old]), /duplicate/);
});
test("normal and retry plans both refuse latest quarantine/review/missing/unknown DQ", () => {
  const it = item(1), existing = point([it, dq(2, it)]);
  for (const verdict of ["quarantine", "review", "invalid"]) {
    const snapshot = latestIntelSnapshot([it, dq(2, it), dq(3, it, verdict)]);
    for (const opts of [{}, { retryIds: ["intel_test"] }]) {
      const plan = planIntelSync(snapshot, [existing], model, opts);
      assert.equal(plan.upsert.length, 0); assert.equal(plan.revoke.length, 1);
    }
    assert.deepEqual(planIntelSync(snapshot, [existing], model, { retryIds: ["intel_test"] }).blocked_retry_ids, ["intel_test"]);
  }
  assert.deepEqual(planIntelSync(latestIntelSnapshot([it]), [existing], model, { retryIds: ["intel_test"] }).blocked_retry_ids, ["intel_test"]);
});
test("updates and metadata changes replace same stable point; unchanged is truly idempotent", () => {
  const old = item(1), existing = point([old, dq(2, old)]), current = item(3, "intel_test", "changed");
  const snapshot = latestIntelSnapshot([old, dq(2, old), current, dq(4, current)]);
  const plan = planIntelSync(snapshot, [existing], model);
  assert.equal(plan.upsert.length, 1); assert.match(plan.upsert[0]!.text, /changed/);
  const freshPoint = point([current, dq(4, current)]);
  assert.equal(planIntelSync(snapshot, [freshPoint], model).unchanged, 1);
  assert.equal(planIntelSync(snapshot, [freshPoint], model, { retryIds: ["intel_test"] }).upsert.length, 1);
  const metaDq = dq(5, current); (metaDq.payload as QualityVerdict).quality_score = 0.7;
  assert.equal(planIntelSync(latestIntelSnapshot([current, metaDq]), [freshPoint], model).upsert.length, 1);
});
test("limit is after latest dedupe and retry never admits unknown ID", () => {
  const a = item(1, "intel_a"), a2 = item(3, "intel_a", "latest"), b = item(5, "intel_b");
  const snapshot = latestIntelSnapshot([b, dq(6, b), a, dq(2, a), a2, dq(4, a2)]);
  const plan = planIntelSync(snapshot, [], model, { limit: 1 });
  assert.equal(plan.upsert.length, 1); assert.match(plan.upsert[0]!.text, /latest/);
  assert.equal(planIntelSync(snapshot, [], model, { retryIds: ["intel_b"] }).upsert[0]!.chunk_id, "intel_b");
  assert.deepEqual(planIntelSync(snapshot, [], model, { retryIds: ["intel_unknown"] }).blocked_retry_ids, ["intel_unknown"]);
});
test("derived summaries keep honest trust, dates, quality, canonical URL and change hash", () => {
  const it = item(1), entry = [...latestIntelSnapshot([it, dq(2, it)]).accepted.values()][0]!;
  const chunk = intelSummaryChunk(entry, 20);
  assert.equal(chunk.trust, "untrusted"); assert.equal(chunk.published_at, sample.published_at);
  assert.equal(chunk.quality_score, 0.95); assert.match(chunk.provenance.url, /nvd.nist.gov\/vuln\/detail\/CVE-/);
  assert.match(chunk.provenance.section, /raw-hash-unverified/); assert.match(chunk.text, /截断/);
  assert.match(chunk.provenance.sha256!, /^[a-f0-9]{64}$/);
});
test("invalid parameters, foreign points, incompatible model and ID collisions fail before mutation", () => {
  const it = item(1), snapshot = latestIntelSnapshot([it, dq(2, it)]), p = point([it, dq(2, it)]);
  for (const n of [-1, NaN, Infinity, 0.5]) assert.throws(() => planIntelSync(snapshot, [], model, { limit: n }));
  for (const n of [-1, 0, NaN]) assert.throws(() => intelSummaryChunk([...snapshot.accepted.values()][0]!, n));
  assert.throws(() => planIntelSync(snapshot, [{ id: 1, payload: { chunk_id: "foreign" } }], model), /foreign/);
  assert.throws(() => planIntelSync(snapshot, [p], { ...model, model_version: "other" }), /model/);
  assert.throws(() => planIntelSync(snapshot, [{ ...p, payload: { ...p.payload, chunk_id: "intel_other" } }], model), /collision/);
});
test("scroll is complete, authenticated, bounded and rejects partial/invalid responses", async () => {
  const calls: Array<{ body: any; key: string | undefined }> = [];
  const pages = [{ result: { points: [{ id: 1, payload: { chunk_id: "intel_a" } }], next_page_offset: "next" } }, { result: { points: [], next_page_offset: null } }];
  const opts = { url: "http://127.0.0.1:1", collection: "test", apiKey: "test-only", fetchImpl: (async (_url, init) => {
    calls.push({ body: JSON.parse(String(init?.body)), key: (init?.headers as Record<string, string>)["api-key"] });
    return Response.json(pages.shift());
  }) as typeof fetch };
  assert.equal((await readIntelPoints(opts)).length, 1); assert.equal(calls[1]!.body.offset, "next"); assert.equal(calls[0]!.key, "test-only");
  for (const status of [401, 503]) await assert.rejects(readIntelPoints({ ...opts, fetchImpl: (async () => new Response("down", { status })) as typeof fetch }), /scroll failed/);
  await assert.rejects(readIntelPoints({ ...opts, fetchImpl: (async () => Response.json({})) as typeof fetch }), /invalid/);
  assert.deepEqual(await readIntelPoints({ ...opts, fetchImpl: (async () => new Response("none", { status: 404 })) as typeof fetch }), []);
  await assert.rejects(readIntelPoints({ ...opts, fetchImpl: (async () => Response.json({ result: { points: [], next_page_offset: 1 } })) as typeof fetch }), /loop/);
});
test("revocation requires successful completed response, not merely a 200", async () => {
  const opts = { url: "http://127.0.0.1:1", collection: "test", fetchImpl: (async () => Response.json({ result: { status: "completed" } })) as typeof fetch };
  await revokeIntelPoints([1], opts);
  await assert.rejects(revokeIntelPoints([1], { ...opts, fetchImpl: (async () => Response.json({ result: { status: "acknowledged" } })) as typeof fetch }), /not completed/);
});
test("dry-run never mutates; apply revokes first and rechecks snapshot; blocked retry writes nothing", async () => {
  const it = item(1), events = [it, dq(2, it)], snapshot = latestIntelSnapshot(events);
  const actions: string[] = [];
  const opts = { snapshot, points: [{ id: 2, payload: { chunk_id: "intel_revoked" } }], model,
    readSnapshot: () => snapshot, write: async () => { actions.push("write"); }, revoke: async () => { actions.push("revoke"); }, cleanup: async () => { actions.push("cleanup"); } };
  const preview = await syncIntelIndex(opts); assert.equal(preview.dry_run, true); assert.deepEqual(actions, []);
  const applied = await syncIntelIndex({ ...opts, apply: true }); assert.equal(applied.written, 1); assert.deepEqual(actions, ["revoke", "write"]);
  actions.length = 0;
  await assert.rejects(syncIntelIndex({ ...opts, apply: true, retryIds: ["intel_no_dq"] }), /not released/); assert.deepEqual(actions, ["revoke"]);
  await assert.rejects(syncIntelIndex({ ...opts, apply: true, readSnapshot: () => latestIntelSnapshot([...events, dq(3, it, "quarantine")]) }), /snapshot changed/);
});
test("partial write/failure or DQ drift cleans attempted points and never reports success", async () => {
  const it = item(1), snapshot = latestIntelSnapshot([it, dq(2, it)]);
  const removed: (string | number)[][] = []; let current = snapshot;
  const opts = { snapshot, points: [], model, apply: true, readSnapshot: () => current,
    write: async (_chunks: unknown, markPutAttempted: () => void) => { markPutAttempted(); current = latestIntelSnapshot([it, dq(2, it), dq(3, it, "quarantine")]); },
    revoke: async () => {}, cleanup: async (ids: readonly string[]) => { removed.push(ids.map(qdrantPointId)); } };
  await assert.rejects(syncIntelIndex(opts), /snapshot changed/); assert.deepEqual(removed, [[qdrantPointId("intel_test")]]);
  current = snapshot; removed.length = 0;
  await assert.rejects(syncIntelIndex({ ...opts, write: async (_chunks, markPutAttempted) => { markPutAttempted(); throw new Error("partial put"); } }), /partial put/);
  assert.deepEqual(removed, [[qdrantPointId("intel_test")]]);
  for (const batchSize of [0, -1, NaN]) await assert.rejects(syncIntelIndex({ ...opts, batchSize }), /INTEL_BATCH/);
});
test("SQLite adapter sorts seq, binds DQ, and refuses corrupt events rather than resurrecting old pass", () => {
  const dir = mkdtempSync(join(tmpdir(), "safetrace-index-")), path = join(dir, "db.sqlite");
  const db = new DatabaseSync(path);
  try {
    db.exec("CREATE TABLE events(seq INTEGER,event_id TEXT,trace_id TEXT,causation_id TEXT,topic TEXT,payload TEXT)");
    const insert = db.prepare("INSERT INTO events VALUES(?,?,?,?,?,?)");
    const it = item(1), q = dq(2, it);
    for (const e of [q, it]) insert.run(e.seq, e.event_id, e.trace_id, e.causation_id, e.topic, JSON.stringify(e.payload));
    assert.equal(readIntelIndexSnapshot(path).accepted.size, 1);
    insert.run(3, "bad", "tr", it.event_id, "dq.verdicts", "{invalid");
    assert.throws(() => readIntelIndexSnapshot(path), /malformed/);
  } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("malformed latest item or DQ cannot resurrect a historical released version", () => {
  const it = item(1), q = dq(2, it);
  for (const patch of [{ dimension_scores: {} }, { quality_score: NaN }, { flags: null }, { gate_version: "" }]) {
    const newer = { ...dq(3, it), payload: { ...q.payload as object, ...patch } };
    // JSON storage cannot contain NaN: reject before fingerprinting or fail the entire snapshot.
    if (Number.isNaN((patch as { quality_score?: number }).quality_score)) assert.throws(() => latestIntelSnapshot([it,q,newer]));
    else assert.equal(latestIntelSnapshot([it,q,newer]).accepted.size, 0);
  }
  const invalid = item(3); (invalid.payload as IntelItem).entities = {} as IntelItem["entities"];
  assert.equal(latestIntelSnapshot([it,q,invalid,dq(4,invalid)]).accepted.size, 0);
});
