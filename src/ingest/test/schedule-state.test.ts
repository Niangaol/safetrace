import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { MemorySourceScheduleStore, SqliteSourceScheduleStore } from "../src/schedule-state.js";
import type { SourceScheduleState } from "../src/schedule-state.js";
const state: SourceScheduleState = { source_id: "nvd_cve", last_attempt_at: "2026-10-01T00:00:00Z", last_success_at: "2026-09-30T00:00:00Z", next_due_at: "2026-10-01T02:00:00Z", consecutive_failures: 2, status: "partial" };
test("schedule-state: memory stores defensive copies", async () => {
  const store = new MemorySourceScheduleStore();
  await store.set(state);
  const read = (await store.get(state.source_id))!;
  read.last_success_at = null;
  assert.deepEqual(await store.get(state.source_id), state);
  assert.equal(await store.get("missing"), undefined);
});
test("schedule-state: SQLite restart retains failures, due time and coverage independently", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "schedule-state-"));
  const filename = path.join(dir, "state.sqlite");
  try {
    const first = new SqliteSourceScheduleStore(filename);
    await first.set(state);
    first.close();
    const second = new SqliteSourceScheduleStore(filename);
    assert.deepEqual(await second.get(state.source_id), state);
    await second.set({ ...state, status: "complete", consecutive_failures: 0 });
    assert.equal((await second.get(state.source_id))?.consecutive_failures, 0);
    second.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
