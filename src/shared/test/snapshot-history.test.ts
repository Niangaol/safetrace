import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import type { EventStore, StoredPageSnapshot } from "../src/store.js";
import { sha256 } from "../src/lineage.js";

function snapshot(text: string, day: string): StoredPageSnapshot {
  return { source_url: "https://vendor.example/advisory", final_url: "https://vendor.example/advisory", title: "Advisory", text, fetched_at: "2026-09-" + day + "T00:00:00.000Z", provider: "direct", content_sha256: sha256(text), lineage_ids: ["ln_" + day] };
}
async function exercise(store: EventStore) {
  const original = snapshot("Original page used for human review", "28");
  await store.saveLastGoodPageSnapshot(original);
  await store.enqueueReviewCase({ review_id: "rv_original", trace_id: "tr_original", source_url: original.source_url, page_sha256: original.content_sha256, title: original.title, reason: "needs evidence review", lineage_id: "ln_review", created_at: original.fetched_at });
  const replacement = snapshot("Updated vendor page", "30");
  await store.saveLastGoodPageSnapshot(replacement);
  assert.equal((await store.getLastGoodPageSnapshot(original.source_url))?.text, replacement.text);
  assert.deepEqual(await store.getLastGoodPageSnapshotByHash(original.content_sha256), original);
  const oldArrival = snapshot("Late arriving older payload", "27");
  assert.equal(await store.saveLastGoodPageSnapshot(oldArrival), false);
  assert.equal((await store.getLastGoodPageSnapshotByHash(oldArrival.content_sha256))?.text, oldArrival.text);
  assert.equal((await store.getLastGoodPageSnapshot(original.source_url))?.text, replacement.text);
  await store.saveLastGoodPageSnapshot({ ...original, fetched_at: replacement.fetched_at, title: "new metadata", lineage_ids: ["ln_new"] });
  assert.deepEqual(await store.getLastGoodPageSnapshotByHash(original.content_sha256), original, "hash-addressed original metadata is not overwritten");
  const review = await store.getReviewCase("rv_original");
  assert.equal((await store.getLastGoodPageSnapshotByHash(review!.page_sha256))?.text, original.text);
  return original;
}

test("existing URL-only snapshot cache is migrated without losing its page", async () => {
  const directory = await mkdtemp(join(tmpdir(), "safetrace-migrate-"));
  const path = join(directory, "old.sqlite");
  const page = snapshot("Cached before history migration", "28");
  const legacy = new DatabaseSync(path);
  legacy.exec("CREATE TABLE last_good_pages (source_url TEXT PRIMARY KEY, final_url TEXT NOT NULL, title TEXT NOT NULL, text TEXT NOT NULL, fetched_at TEXT NOT NULL, provider TEXT NOT NULL, content_sha256 TEXT NOT NULL, lineage_ids TEXT NOT NULL)");
  legacy.prepare("INSERT INTO last_good_pages VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(page.source_url, page.final_url, page.title, page.text, page.fetched_at, page.provider, page.content_sha256, JSON.stringify(page.lineage_ids));
  legacy.close();
  const store = new SqliteEventStore(path);
  try {
    await store.saveLastGoodPageSnapshot(snapshot("New version after migration", "30"));
    assert.deepEqual(await store.getLastGoodPageSnapshotByHash(page.content_sha256), page);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test("Memory snapshots retain review evidence after URL replacement", async () => {
  await exercise(new MemoryEventStore());
});

test("SQLite snapshot history retains old review evidence across restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "safetrace-history-"));
  const path = join(directory, "history.sqlite");
  const first = new SqliteEventStore(path);
  let original: StoredPageSnapshot;
  try { original = await exercise(first); } finally { first.close(); }
  const second = new SqliteEventStore(path);
  try {
    const review = await second.getReviewCase("rv_original");
    assert.deepEqual(await second.getLastGoodPageSnapshotByHash(review!.page_sha256), original!);
  } finally { second.close(); await rm(directory, { recursive: true, force: true }); }
});
