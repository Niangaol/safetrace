/**
 * E-04 回归：DQ1 隔离区落库（quarantine 表）——可查、可导出、判定可复算。
 * 口径：fixtures/dirty/ 十条脏样本的 quarantine 判定必须全部落表；
 * review/degrade/pass 不混入隔离区；quarantine_ref 为幂等键。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemoryEventStore, SqliteEventStore } from "@safetrace/shared";
import type { IntelItem, QualityVerdict } from "@safetrace/shared";
import { assessQualityVerdict, quarantineReason, recordQuarantine } from "../src/dq1.js";

const DIRTY_QUARANTINE = [
  "dirty-01-reject-status.json",
  "dirty-02-reserved-status.json",
  "dirty-03-ts-future.json",
  "dirty-04-ts-ancient.json",
  "dirty-05-key5-missing.json",
  "dirty-07-poc-dead-link.json",
];

async function loadItem(name: string): Promise<IntelItem> {
  const p = fileURLToPath(new URL("../../../fixtures/dirty/" + name, import.meta.url));
  return JSON.parse(await readFile(p, "utf8")) as IntelItem;
}

test("E-04：quarantineReason 红线优先、否则质量分不足", () => {
  const redline: QualityVerdict = {
    item_id: "i", item_kind: "intel", quality_score: 0.2,
    dimension_scores: { structure: 0.2, completeness: 0.2, consistency: 0.2, timeliness: 0.2, sourcing: 0.2 },
    flags: ["reject_status"], verdict: "quarantine", gate_version: "1.1.0",
  };
  assert.match(quarantineReason(redline), /reject_status/);
  const lowScore: QualityVerdict = { ...redline, flags: [] };
  assert.match(quarantineReason(lowScore), /0\.20 低于 0\.50/);
});

test("E-04：recordQuarantine 只落 quarantine 判定（review 不混入）", async () => {
  const store = new MemoryEventStore();
  const item = await loadItem("dirty-01-reject-status.json");
  const quarantined = assessQualityVerdict(item);
  await recordQuarantine(store, item, quarantined, "2026-10-10T00:00:00.000Z");
  const rows = await store.quarantineEntries();
  assert.equal(rows.length, 1, "quarantine 判定必须落表");
  assert.equal(rows[0]!.quarantine_ref, "dq_quarantine:" + item.intel_id);
  assert.equal(rows[0]!.intel_id, item.intel_id);
  assert.match(rows[0]!.reason, /reject_status/);
  assert.deepEqual(rows[0]!.verdict, quarantined, "verdict 原样留存可复算");
  // 幂等：同一 quarantine_ref 重复落库不产生第二行
  await recordQuarantine(store, item, quarantined, "2026-10-10T00:00:01.000Z");
  assert.equal((await store.quarantineEntries()).length, 1);
  // review 判定不落隔离区（走人工复核队列，不混入）
  const reviewItem = await loadItem("dirty-09-multi-id-mismatch.json");
  const review = assessQualityVerdict(reviewItem);
  assert.equal(review.verdict, "review");
  await recordQuarantine(store, reviewItem, review, "2026-10-10T00:00:00.000Z");
  assert.equal((await store.quarantineEntries()).length, 1, "review 不得混入隔离区");
});

test("E-04：fixtures/dirty 六条 quarantine 全部落表（验收口径）", async () => {
  const store = new MemoryEventStore();
  for (const name of DIRTY_QUARANTINE) {
    const item = await loadItem(name);
    const verdict = assessQualityVerdict(item);
    assert.equal(verdict.verdict, "quarantine", name + " 应判 quarantine");
    assert.ok(verdict.quarantine_ref, name + " 必须带 quarantine_ref");
    await recordQuarantine(store, item, verdict, "2026-10-10T00:00:00.000Z");
  }
  const rows = await store.quarantineEntries();
  assert.equal(rows.length, DIRTY_QUARANTINE.length, "六条脏样本全部落表");
});

test("E-04：SQLite 隔离区跨重启保留（可查可导出的持久化前提）", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-quarantine-"));
  const dbPath = join(dir, "safetrace.sqlite");
  try {
    const item = await loadItem("dirty-03-ts-future.json");
    const verdict = assessQualityVerdict(item);
    const first = new SqliteEventStore(dbPath);
    await recordQuarantine(first, item, verdict, "2026-10-10T00:00:00.000Z");
    first.close();
    const second = new SqliteEventStore(dbPath);
    const rows = await second.quarantineEntries();
    second.close();
    assert.equal(rows.length, 1, "重开库后隔离区记录仍在");
    assert.equal(rows[0]!.quarantine_ref, verdict.quarantine_ref);
    assert.deepEqual(rows[0]!.verdict.dimension_scores, verdict.dimension_scores);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});