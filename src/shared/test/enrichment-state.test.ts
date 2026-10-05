import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SqliteEnrichmentStateStore, enrichmentInputHash, enrichmentRetryAfter, enrichmentRetryDue } from "../src/enrichment-state.js";
import { sha256Json } from "../src/lineage.js";
import type { IntelItem } from "../src/types.js";
const item = { intel_id: "a", first_seen_at: "2026-10-01", title: "facts" } as IntelItem;
test("fact hash ignores first_seen but detects title change", () => {
 assert.equal(enrichmentInputHash(item), enrichmentInputHash({ ...item, first_seen_at: "2026-10-02" }));
 assert.notEqual(enrichmentInputHash(item), enrichmentInputHash({ ...item, title: "new facts" }));
});
test("durable state survives reopen, readOnly cannot initialize or mutate", () => {
 const dir = mkdtempSync(join(tmpdir(), "enrich-state-")); const path = join(dir, "state.sqlite");
 try {
  const db = new DatabaseSync(path); db.close();
  let store = new SqliteEnrichmentStateStore(path, { readOnly: true }); assert.deepEqual(store.list(), []); store.close();
  store = new SqliteEnrichmentStateStore(path);
  const now = new Date("2026-10-04T00:00:00Z");
  const row = { intel_id: "a", dimension: "paper" as const, status: "empty" as const, input_hash: enrichmentInputHash(item), result_hash: sha256Json([]), enrich_event_id: "ev_a", retry_after: enrichmentRetryAfter("empty", 1, now), reason: "no relevant papers", attempts: 1, updated_at: now.toISOString(), artifact: [] };
  store.put(row); store.close(); store = new SqliteEnrichmentStateStore(path, { readOnly: true });
  assert.deepEqual(store.get("a", "paper"), row); assert.throws(() => store.put(row), /read-only/);
  assert.equal(enrichmentRetryDue(row, row.input_hash, now), false);
  assert.equal(enrichmentRetryDue(row, "changed", now), true);
  assert.equal(enrichmentRetryDue(row, row.input_hash, new Date("2026-10-05T00:00:01Z")), true);
  assert.equal(enrichmentRetryDue({ ...row, status: "live" }, row.input_hash, now), false);
  assert.ok(Date.parse(enrichmentRetryAfter("failed", 2, now)!) > Date.parse(enrichmentRetryAfter("failed", 1, now)!));
  store.close();
 } finally { rmSync(dir, { recursive: true, force: true }); }
});
