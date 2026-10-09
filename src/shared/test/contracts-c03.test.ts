/**
 * C-03 契约位回归：QualityVerdict 追加可选 injection_score / injection_flags。
 * 只验证契约位与"缺省 = 未筛查"语义，不实现也不宣称注入检测能力（检测归 A-04）。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateInstance } from "../src/schema.js";
import type { QualityVerdict } from "../src/types.js";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const parse = (rel: string): unknown => JSON.parse(read(rel)) as unknown;

/** events.md 内联契约的手工镜像（内联契约无独立 schema 文件，按同字段集做实例校验）。 */
const C03_ADDED: Record<string, unknown> = {
  injection_score: { type: "number", minimum: 0, maximum: 1 },
  injection_flags: { type: "array", items: { type: "string", enum: [
    "instruction_override", "role_confusion", "zero_width_chars", "base64_hidden",
    "html_entity_encoded", "comment_embedded", "exfil_instruction",
    "fake_system_prompt", "citation_spoof", "multi_stage",
  ] } },
};
const BASE: Record<string, unknown> = {
  type: "object", additionalProperties: false,
  required: ["item_id", "item_kind", "quality_score", "dimension_scores", "flags", "verdict", "gate_version"],
  properties: {
    quarantine_ref: { type: "string" },
    reviewer: { type: "string" },
    reviewed_at: { type: "string" },
    item_id: { type: "string" }, item_kind: { type: "string" },
    quality_score: { type: "number", minimum: 0, maximum: 1 },
    dimension_scores: { type: "object" },
    flags: { type: "array" },
    verdict: { type: "string", enum: ["pass", "degrade", "review", "quarantine"] },
    gate_version: { type: "string" },
    ...C03_ADDED,
  },
};

test("QualityVerdict：新字段可选，旧形状与带新字段的形状都合法", () => {
  const mirrored = parse("fixtures/qualityverdict.sample.json");
  assert.deepEqual(validateInstance(mirrored, BASE), [], "旧样例（无新字段）必须仍合法：纯追加、向后兼容");
  const extended = parse("fixtures/qualityverdict.injection.sample.json");
  assert.deepEqual(validateInstance(extended, BASE), [], "带 injection_* 的样例必须合法");
  const verdict = extended as QualityVerdict;
  assert.equal(typeof verdict.injection_score, "number");
  assert.ok((verdict.injection_flags ?? []).length > 0);
});

test("QualityVerdict：越界评分与未知注入标签必须被拒", () => {
  const base = JSON.parse(JSON.stringify(parse("fixtures/qualityverdict.sample.json"))) as Record<string, unknown>;
  base.injection_score = 1.5;
  assert.ok(validateInstance(base, BASE).length > 0, "injection_score 越界必须被拒");
  const unknown = JSON.parse(JSON.stringify(base)) as Record<string, unknown>;
  unknown.injection_score = 0.5;
  unknown.injection_flags = ["totally_unknown"];
  assert.ok(validateInstance(unknown, BASE).length > 0, "未知注入标签必须被拒");
});

test("内联契约与 TS 镜像已登记 C-03；A-04 落地后 DQ1 如实填充且不宣称保证", () => {
  const events = read("contracts/events.md");
  assert.match(events, /injection_score/, "events.md 内联契约须登记新字段");
  assert.match(events, /injection_flags/, "events.md 内联契约须登记新字段");
  const mirror = read("src/shared/src/types.ts");
  assert.match(mirror, /export type InjectionFlag/, "TS 镜像须同步 InjectionFlag");
  assert.match(mirror, /injection_score\?: number;/, "TS 镜像须同步 injection_score");
  const changelog = read("contracts/schemas/CHANGELOG.md");
  assert.match(changelog, /C-03/, "须在 CHANGELOG 登记影响面");
  // A-04 已落地（2026-10-09）：DQ1 经共享启发式填充两个字段；仍不得宣称"保证安全"
  const dq = read("src/ingest/src/dq1.ts");
  assert.match(dq, /screenPromptInjection/, "DQ1 必须复用共享筛查器，不得另造一套口径");
  assert.match(dq, /injection_flags/, "DQ1 必须填充 injection_flags");
  assert.match(dq, /injection_score/, "DQ1 必须填充 injection_score");
  assert.ok(!/guarantee|保证/.test(dq), "启发式筛查不得写成安全保证");
});
