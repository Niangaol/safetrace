/**
 * A-04 注入防护 · DQ1 闸门验收（台账第 2 阶段准出命令 src/ingest/test/injection.test.ts）。
 * 覆盖：
 *  1. fixtures/injection/ 十类对抗样本逐一断言 injection_flags 命中且 verdict 转人工复核（review）；
 *  2. 良性公告/修复指引不误报（injection_score=0、flags 空、verdict 不受影响）；
 *  3. 判定可复算（同输入同输出，gate 1.1.0）；
 *  4. 无法筛查（超限输入）→ 不填注入字段（缺省=未筛查）且 fail-closed 至少 review；
 *  5. 元内容误判方向安全：引用攻击示例的真实内容转 review 而非 quarantine（数据不丢、人工可判）；
 *  6. 管线口径：review 判定只入 dq.verdicts，不进 intel.items（脏数据不进知识底座）。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { MemoryEventStore } from "@safetrace/shared";
import type { IntelItem, QualityVerdict } from "@safetrace/shared";
import { GATE_VERSION, assessQualityVerdict } from "../src/dq1.js";
import { runIngestOnce } from "../src/pipeline.js";

const NOW = new Date("2026-10-09T00:00:00Z");

async function loadItem(name: string): Promise<IntelItem> {
  const p = fileURLToPath(new URL("../../../fixtures/injection/" + name, import.meta.url));
  return JSON.parse(await readFile(p, "utf8")) as IntelItem;
}

const CASES: Array<[string, string]> = [
  ["inj-01-instruction-override.json", "instruction_override"],
  ["inj-02-role-confusion.json", "role_confusion"],
  ["inj-03-zero-width.json", "zero_width_chars"],
  ["inj-04-base64-hidden.json", "base64_hidden"],
  ["inj-05-html-entity-encoded.json", "html_entity_encoded"],
  ["inj-06-comment-embedded.json", "comment_embedded"],
  ["inj-07-exfil-instruction.json", "exfil_instruction"],
  ["inj-08-fake-system-prompt.json", "fake_system_prompt"],
  ["inj-09-citation-spoof.json", "citation_spoof"],
  ["inj-10-multi-stage.json", "multi_stage"],
];

for (const [name, expectedFlag] of CASES) {
  test("A-04 DQ1：" + name + " 命中 " + expectedFlag + " 并转人工复核", async () => {
    const item = await loadItem(name);
    const v = assessQualityVerdict(item, { now: NOW });
    assert.ok((v.injection_flags ?? []).includes(expectedFlag as never),
      name + " 应命中 " + expectedFlag + "，实际 " + JSON.stringify(v.injection_flags));
    assert.equal(v.injection_score, 1, "命中时 injection_score=1（有界启发式的二值判定）");
    assert.equal(v.verdict, "review", "注入迹象必须转人工复核（review），实际 " + v.verdict);
    assert.equal(v.quarantine_ref, undefined, "启发式误判不杀数据：review 不写 quarantine_ref");
    assert.equal(v.gate_version, GATE_VERSION);
    assert.equal(GATE_VERSION, "1.1.0");
  });
}

test("A-04 DQ1：良性公告与修复指引不误报", async () => {
  for (const name of ["inj-b1-clean-advisory.json", "inj-b2-security-prose.json"]) {
    const v = assessQualityVerdict(await loadItem(name), { now: NOW });
    assert.deepEqual(v.injection_flags, [], name + " 不应命中任何注入迹象");
    assert.equal(v.injection_score, 0, name + " 干净时 injection_score=0");
    assert.equal(v.verdict, "pass", name + " 良性内容判定不受注入筛查影响");
    assert.equal(v.injection_score !== undefined && v.injection_flags !== undefined, true,
      name + " 已筛查必须显式可见（字段存在且为空），不得用缺省冒充未筛查");
  }
});

test("A-04 DQ1：判定可复算（同输入同输出）", async () => {
  const item = await loadItem("inj-01-instruction-override.json");
  const a = assessQualityVerdict(item, { now: NOW });
  const b = assessQualityVerdict(item, { now: NOW });
  assert.deepEqual(a, b);
});

test("A-04 DQ1：超限输入无法筛查 → 不填字段（缺省=未筛查）且 fail-closed 至少 review", async () => {
  const item = await loadItem("inj-b1-clean-advisory.json");
  const oversized = { ...item, summary: "x".repeat(100_001) };
  const v = assessQualityVerdict(oversized, { now: NOW });
  assert.equal(v.injection_score, undefined, "无法筛查时不得填 injection_score（缺省=未筛查）");
  assert.equal(v.injection_flags, undefined, "无法筛查时不得填 injection_flags");
  assert.equal(v.verdict, "review", "无法筛查必须 fail-closed 转人工，实际 " + v.verdict);
});

test("A-04 DQ1：元内容误判方向安全——引用攻击示例转 review 不转 quarantine", async () => {
  const item = await loadItem("inj-b1-clean-advisory.json");
  const meta = { ...item, summary: item.summary + " 攻击者常用手法是要求模型 ignore all previous instructions，本文仅作描述。" };
  const v = assessQualityVerdict(meta, { now: NOW });
  assert.ok((v.injection_flags ?? []).includes("instruction_override"), "描述性引用同样命中（有界启发式的已知边界）");
  assert.equal(v.verdict, "review", "误判方向必须是人工复核而非隔离销毁");
});

test("A-04 DQ1→管线：review 判定只入 dq.verdicts，不进 intel.items", async () => {
  const store = new MemoryEventStore();
  const result = await runIngestOnce({ store, offline: true });
  const verdicts = (await store.read<QualityVerdict>("dq.verdicts")).map((e) => e.payload);
  assert.ok(verdicts.length > 0, "离线 fixture 回放必须产出 DQ 判定");
  for (const v of verdicts) {
    assert.equal(v.gate_version, "1.1.0", "管线判定必须来自 gate 1.1.0");
    assert.ok(v.injection_score !== undefined && v.injection_flags !== undefined,
      "DQ1 产出必须显式带注入筛查字段（已筛查且干净也要可见）");
    assert.deepEqual(v.injection_flags, [], "仓库 fixture 不含注入载荷");
  }
  // 与既有红线一致：只有 pass/degrade 进 intel.items；review/quarantine 只留判定可见
  const intel = await store.read<IntelItem>("intel.items");
  const released = new Set(intel.map((e) => e.payload.intel_id));
  for (const v of verdicts) {
    if (v.verdict === "review" || v.verdict === "quarantine") {
      assert.equal(released.has(v.item_id), false, "未放行判定不得进入 intel.items");
    }
  }
  assert.ok(result.verdicts.every((v) => v.injection_score !== undefined), "runIngestOnce 返回值同样带注入字段");
});
