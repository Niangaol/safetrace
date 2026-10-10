import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import type { ThreadCheckpoint } from "../src/store.js";

for (const backend of ["memory", "sqlite"] as const) {
  test("thread lease owner CAS and fingerprint: " + backend, async () => {
    const dir = await mkdtemp(join(tmpdir(), "safetrace-thread-lease-"));
    const path = join(dir, "threads.sqlite");
    const a = backend === "memory" ? new MemoryEventStore() : new SqliteEventStore(path);
    const b = backend === "memory" ? a : new SqliteEventStore(path);
    try {
      const winners = await Promise.all([a.acquireThreadLease("thread", "a"), b.acquireThreadLease("thread", "b")]);
      assert.deepEqual(winners, [true, false]);
      assert.equal(await b.releaseThreadLease("thread", "b"), false);
      assert.equal(await b.acquireThreadLease("thread", "b"), false);
      const cp: ThreadCheckpoint = { thread_id: "thread", trace_id: "tr", executed: ["first"], interrupt_node_id: "second", state: { value: 1 }, status: "failed", spec_fingerprint: "graph.v2:sha256", updated_at: new Date().toISOString() };
      await a.saveThreadCheckpoint(cp);
      assert.deepEqual(await b.loadThreadCheckpoint("thread"), cp);
      assert.deepEqual(await b.threadCheckpoints(), [cp]);
      if (backend === "sqlite") {
        const reopened = new SqliteEventStore(path);
        try {
          assert.equal(await reopened.acquireThreadLease("thread", "after-crash"), false, "lock never expires on reopen");
          assert.deepEqual(await reopened.loadThreadCheckpoint("thread"), cp);
        } finally { reopened.close(); }
      }
      assert.equal(await a.releaseThreadLease("thread", "a"), true);
      assert.equal(await b.acquireThreadLease("thread", "b"), true);
      assert.equal(await a.releaseThreadLease("thread", "a"), false);
    } finally { a.close(); if (b !== a) b.close(); await rm(dir, { recursive: true, force: true }); }
  });
}

test("thread fingerprint migration preserves legacy checkpoint without inventing graph identity", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-thread-migrate-"));
  const path = join(dir, "legacy.sqlite");
  try {
    const old = new DatabaseSync(path);
    old.exec("CREATE TABLE machine_threads (thread_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, executed TEXT NOT NULL, interrupt_node_id TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL)");
    old.prepare("INSERT INTO machine_threads VALUES (?, ?, ?, ?, ?, ?, ?)").run("legacy", "tr", "[]", "node", "{}", "suspended", "2026-01-01");
    old.close();
    for (let i = 0; i < 2; i++) {
      const store = new SqliteEventStore(path);
      try {
        const checkpoint = await store.loadThreadCheckpoint("legacy");
        assert.equal(checkpoint?.status, "suspended");
        assert.ok(!("spec_fingerprint" in checkpoint!));
      } finally { store.close(); }
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
