import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { MemoryUpdateQueue, SQLiteUpdateQueue } from "../src/orchestrator/update-queue.js";
import type { UpdateDraft, UpdateQueue } from "../src/orchestrator/update-queue.js";
const draft = (seq = 1, id = "intel-a"): UpdateDraft => ({ intel_id: id,
  intel_event_seq: seq, input_hash: "hash-" + seq, refs: ["event-" + seq, "raw-ref"], detected_at: 10 });

for (const mode of ["memory", "sqlite"] as const) {
  async function setup(fn: (q: UpdateQueue, setNow: (n: number) => void) => void) {
    let now = 20;
    const dir = mode === "sqlite" ? await mkdtemp(join(tmpdir(), "safetrace-update-")) : null;
    const opts = { clock: () => now, backoffBaseMs: 10, backoffMaxMs: 30, maxAttempts: 3 };
    const q = dir ? new SQLiteUpdateQueue(join(dir, "queue.sqlite"), opts) : new MemoryUpdateQueue(opts);
    try { fn(q, n => { now = n; }); }
    finally { q.close(); if (dir) await rm(dir, { recursive: true, force: true }); }
  }
  test(mode + ": version coalescing, no duplicate redispatch and exact timestamps", () => setup((q, now) => {
    assert.equal(q.enqueue(draft()).reason, "new");
    assert.equal(q.claim("index", "i"), null);
    now(30); const c = q.claim("enrich", "e")!;
    assert.equal(q.claim("enrich", "other"), null);
    assert.equal(q.enqueue(draft()).reason, "duplicate");
    assert.equal(q.enqueue({ ...draft(), input_hash: "conflict" }).reason, "conflict");
    assert.equal(q.isCurrent(c), true);
    now(40); assert.equal(q.complete(c), true);
    assert.equal(q.complete(c), false);
    now(50); const i = q.claim("index", "i")!;
    now(60); assert.equal(q.complete(i), true);
    const t = q.get("intel-a")!;
    assert.deepEqual([t.detected_at,t.enqueued_at,t.started_at,t.enriched_at,t.index_started_at,t.indexed_at], [10,20,30,40,50,60]);
    assert.equal(q.enqueue(draft()).reason, "duplicate");
    assert.equal(q.claim("enrich", "e"), null);
    assert.equal(q.claim("index", "i"), null);
  }));
  test(mode + ": new version fences late complete/fail, including same hash", () => setup(q => {
    q.enqueue(draft(2)); const old = q.claim("enrich", "old")!;
    assert.equal(q.enqueue(draft()).reason, "stale");
    assert.equal(q.enqueue({ ...draft(3), input_hash: old.input_hash }).reason, "replaced");
    assert.equal(q.isCurrent(old), false);
    assert.equal(q.complete(old), false); assert.equal(q.fail(old), false);
    const current = q.claim("enrich", "new")!;
    assert.equal(current.intel_event_seq, 3);
    assert.equal(q.complete({ ...current, token: "forged" }), false);
    assert.equal(q.complete(current), true);
  }));
  test(mode + ": expiration boundary, recovery token and bounded exponential retries", () => setup((q, now) => {
    q.enqueue(draft()); const old = q.claim("enrich", "a", 20, 10)!;
    now(29); assert.equal(q.isCurrent(old), true); assert.equal(q.claim("enrich", "b"), null);
    now(30); assert.equal(q.isCurrent(old), false); assert.equal(q.complete(old), false);
    const c = q.claim("enrich", "b")!;
    assert.notEqual(c.token, old.token); assert.equal(q.fail(old), false);
    assert.equal(q.fail(c), true); assert.equal(q.get(c.intel_id)!.next_attempt_at, 50);
    now(49); assert.equal(q.claim("enrich", "c"), null);
    now(50); const last = q.claim("enrich", "c")!;
    assert.equal(q.fail(last), true); assert.equal(q.get(c.intel_id)!.status, "blocked");
    now(1000); assert.equal(q.claim("enrich", "d"), null);
  }));
  test(mode + ": revoke persists watermark fence and newer event restores", () => setup(q => {
    q.enqueue(draft()); const old = q.claim("enrich", "a")!;
    assert.equal(q.revoke("missing", 10), false);
    assert.equal(q.revoke(old.intel_id, 5), true);
    assert.equal(q.revoke(old.intel_id, 4), false);
    assert.equal(q.isCurrent(old), false); assert.equal(q.complete(old), false);
    assert.equal(q.claim("enrich", "b"), null);
    assert.equal(q.enqueue(draft(4)).reason, "stale");
    assert.equal(q.enqueue({ ...draft(), refresh_key: "refresh" }).reason, "stale");
    assert.equal(q.enqueue(draft(6)).accepted, true);
    assert.equal(q.claim("enrich", "b")!.intel_event_seq, 6);
  }));
  test(mode + ": refresh only terminal rows, reference-only payload and cloned snapshots", () => setup(q => {
    const d = { ...draft(), private_body: "secret", refresh_key: "r1" };
    q.enqueue(d); const c = q.claim("enrich", "e")!;
    assert.equal(q.enqueue({ ...d, refresh_key: "r2" }).reason, "duplicate");
    assert.equal(q.isCurrent(c), true); q.complete(c);
    q.complete(q.claim("index", "i")!);
    assert.equal(q.enqueue({ ...d, refresh_key: "r2" }).reason, "refreshed");
    assert.equal(q.enqueue({ ...d, refresh_key: "r2" }).reason, "duplicate");
    assert.equal(JSON.stringify(q.list()).includes("secret"), false);
    const t = q.get(d.intel_id)!; t.refs.push("mutated");
    assert.deepEqual(q.get(d.intel_id)!.refs, d.refs);
  }));
  test(mode + ": expired attempt cap blocks and explicit refreshed state permits retry", () => setup(q => {
    q.enqueue(draft());
    q.claim("enrich", "a", 20, 10);
    q.claim("enrich", "b", 30, 10);
    const old = q.claim("enrich", "c", 40, 10)!;
    assert.equal(q.claim("enrich", "d", 50, 10), null);
    assert.equal(q.get("intel-a")!.status, "blocked");
    assert.equal(q.complete(old, 50), false);
    assert.equal(q.enqueue(draft()).reason, "duplicate");
    assert.equal(q.enqueue({ ...draft(), refresh_key: "updated-state" }).reason, "refreshed");
    assert.equal(q.claim("enrich", "d", 50, 10)!.attempts, 1);
    assert.throws(() => q.enqueue({ ...draft(2), refresh_key: {} as string }), /refresh key/);
    assert.throws(() => q.claim("enrich", "d", 50, 0), /duration/);
  }));
  test(mode + ": newest sequence first and higher risk tie-break", () => setup(q => {
    q.enqueue({ ...draft(1, "old"), priority: 100 });
    q.enqueue({ ...draft(2, "low"), priority: 0 });
    q.enqueue({ ...draft(2, "high"), priority: 10 });
    assert.equal(q.claim("enrich", "a")!.intel_id, "high");
    assert.equal(q.claim("enrich", "b")!.intel_id, "low");
    assert.equal(q.claim("enrich", "c")!.intel_id, "old");
  }));
}
test("sqlite: distinct instances atomic claims and restart preserves backoff and index phase", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-update-restart-"));
  const path = join(dir, "queue.sqlite"); const options = { clock: () => 20, backoffBaseMs: 10 };
  let a = new SQLiteUpdateQueue(path, options); const b = new SQLiteUpdateQueue(path, options);
  try {
    a.enqueue(draft());
    const claims = await Promise.all([Promise.resolve().then(() => a.claim("enrich", "a")),
      Promise.resolve().then(() => b.claim("enrich", "b"))]);
    assert.equal(claims.filter(Boolean).length, 1); const c = claims.find(Boolean)!;
    assert.equal(b.fail(c, 21), true);
    a.close(); a = new SQLiteUpdateQueue(path, options);
    assert.equal(a.claim("enrich", "restart", 30), null);
    const next = a.claim("enrich", "restart", 31)!;
    assert.equal(a.complete(next, 32), true);
    a.close(); a = new SQLiteUpdateQueue(path, options);
    assert.equal(a.get(c.intel_id)!.stage, "index");
    assert.equal(a.complete(c, 33), false);
    const index = b.claim("index", "index", 33)!;
    assert.equal(a.complete(index, 34), true); assert.equal(b.complete(index, 34), false);
  } finally { a.close(); b.close(); await rm(dir, { recursive: true, force: true }); }
});

test("sqlite: truly concurrent worker connections claim one token", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-update-workers-"));
  const path = join(dir, "queue.sqlite");
  const q = new SQLiteUpdateQueue(path, { clock: () => 20 });
  const workers: Worker[] = [];
  try {
    q.enqueue(draft());
    const ready: Promise<void>[] = [], results: Promise<unknown>[] = [];
    for (const owner of ["worker-a", "worker-b"]) {
      const worker = new Worker(`
        const { parentPort, workerData } = require("node:worker_threads");
        (async () => {
          const { tsImport } = await import("tsx/esm/api");
          const { SQLiteUpdateQueue } = await tsImport(workerData.url, workerData.url);
          const q = new SQLiteUpdateQueue(workerData.path);
          parentPort.once("message", () => {
            try { parentPort.postMessage({ result: q.claim("enrich", workerData.owner, 20, 100) }); }
            catch (e) { parentPort.postMessage({ error: String(e) }); }
            finally { q.close(); parentPort.close(); }
          });
          parentPort.postMessage({ ready: true });
        })().catch(e => { throw e; });
      `, { eval: true, workerData: { path, owner, url: new URL("../src/orchestrator/update-queue.ts", import.meta.url).href } });
      workers.push(worker);
      ready.push(new Promise((resolve,reject) => {
        worker.on("message", msg => { if (msg.ready) resolve(); }); worker.once("error", reject);
      }));
      results.push(new Promise((resolve,reject) => {
        worker.on("message", msg => { if ("result" in msg) resolve(msg.result); if (msg.error) reject(new Error(msg.error)); });
        worker.once("error", reject);
      }));
    }
    await Promise.all(ready); workers.forEach(w => w.postMessage("go"));
    const claims = await Promise.all(results);
    assert.equal(claims.filter(Boolean).length, 1);
  } finally { await Promise.all(workers.map(w => w.terminate())); q.close(); await rm(dir, { recursive: true, force: true }); }
});
