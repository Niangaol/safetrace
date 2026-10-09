/**
 * DQ1 质量闸门单测（硬验收）：fixtures/dirty/ 十条逐一断言预期 verdict。
 * 01/02/03/04/05/07 → quarantine；06/08/10 → degrade；09 → review。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { DqVerdict, IntelItem } from "@safetrace/shared";
import { GATE_VERSION, assessQualityVerdict } from "../src/dq1.js";

const CASES: Array<[string, DqVerdict]> = [
  ["dirty-01-reject-status.json", "quarantine"], // 硬红线：REJECTED
  ["dirty-02-reserved-status.json", "quarantine"], // 硬红线：RESERVED
  ["dirty-03-ts-future.json", "quarantine"], // 硬红线：晚于 now+5min
  ["dirty-04-ts-ancient.json", "quarantine"], // 硬红线：早于 1999
  ["dirty-05-key5-missing.json", "quarantine"], // 硬红线：关键 5 字段全空
  ["dirty-06-ts-no-tz.json", "degrade"], // ts_no_tz
  ["dirty-07-poc-dead-link.json", "quarantine"], // 硬红线：POC 无 sha256
  ["dirty-08-boilerplate.json", "degrade"], // boilerplate
  ["dirty-09-multi-id-mismatch.json", "review"], // multi_id_mismatch
  ["dirty-10-unknown-version.json", "degrade"], // unknown_version
];

async function loadItem(name: string): Promise<IntelItem> {
  const p = fileURLToPath(new URL("../../../fixtures/dirty/" + name, import.meta.url));
  return JSON.parse(await readFile(p, "utf8")) as IntelItem;
}

for (const [name, expected] of CASES) {
  test("dq1：" + name + " → " + expected, async () => {
    const item = await loadItem(name);
    const v = assessQualityVerdict(item);
    assert.equal(
      v.verdict,
      expected,
      name + " 期望 " + expected + "，实得 " + v.verdict +
        "（score=" + v.quality_score + " flags=[" + v.flags.join(",") + "] dims=" + JSON.stringify(v.dimension_scores) + "）",
    );
    assert.equal(v.item_kind, "intel");
    assert.equal(v.gate_version, GATE_VERSION);
    assert.equal(GATE_VERSION, "1.1.0");
    assert.equal(v.item_id, item.intel_id);
    assert.ok(v.quality_score >= 0 && v.quality_score <= 1);
    for (const d of Object.values(v.dimension_scores)) {
      assert.ok(d >= 0 && d <= 1);
    }
  });
}

test("dq1：干净样本 pass（五维满分、无 flags）", async () => {
  const p = fileURLToPath(new URL("../../../fixtures/intelitem.sample.json", import.meta.url));
  const item = JSON.parse(await readFile(p, "utf8")) as IntelItem;
  const v = assessQualityVerdict(item);
  assert.equal(v.verdict, "pass");
  assert.equal(v.quality_score, 1);
  assert.deepEqual(v.flags, []);
  assert.deepEqual(v.dimension_scores, { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 });
  assert.equal(v.quarantine_ref, undefined);
});

test("dq1：flags 明细（ts_no_tz / boilerplate / multi_id_mismatch / unknown_version / reject_status）", async () => {
  const cases: Array<[string, string[]]> = [
    ["dirty-01-reject-status.json", ["reject_status"]],
    ["dirty-06-ts-no-tz.json", ["ts_no_tz"]],
    ["dirty-08-boilerplate.json", ["boilerplate"]],
    ["dirty-09-multi-id-mismatch.json", ["multi_id_mismatch"]],
    ["dirty-10-unknown-version.json", ["unknown_version"]],
  ];
  for (const [name, expectedFlags] of cases) {
    const v = assessQualityVerdict(await loadItem(name));
    assert.deepEqual(v.flags, expectedFlags, name + " flags 不符");
  }
});

test("dq1：quarantine 带 quarantine_ref；判定可复算（同输入同输出）", async () => {
  const item = await loadItem("dirty-07-poc-dead-link.json");
  const now = new Date("2026-09-28T12:00:00Z");
  const v1 = assessQualityVerdict(item, { now });
  const v2 = assessQualityVerdict(item, { now });
  assert.equal(v1.verdict, "quarantine");
  assert.equal(v1.quarantine_ref, "dq_quarantine:" + item.intel_id);
  assert.deepEqual(v1, v2); // 同版本同输入必须同输出
  assert.deepEqual(v1.flags, ["poc_dead_link"]);
});

test("dq1：review 档可派人工复核人", async () => {
  const item = await loadItem("dirty-09-multi-id-mismatch.json");
  const v = assessQualityVerdict(item, { reviewer: "oncall-zhang" });
  assert.equal(v.verdict, "review");
  assert.equal(v.reviewer, "oncall-zhang");
  assert.ok((v.reviewed_at ?? "").length > 0);
});
