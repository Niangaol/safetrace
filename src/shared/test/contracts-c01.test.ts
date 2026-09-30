/**
 * C-01 契约回归：DecisionReply.decided_by 追加 human（四层兜底人工层）。
 * 只读契约并校验实例，不改冻结契约；枚举被回退或样例失配时这里立刻红。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateInstance } from "../src/schema.js";
import type { DecisionReply } from "../src/types.js";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const parse = (rel: string): unknown => JSON.parse(read(rel)) as unknown;

function decidedByEnum(): string[] {
  const schema = parse("contracts/schemas/DecisionReply.json") as { properties: { decided_by: { enum: string[] } } };
  return schema.properties.decided_by.enum;
}

test("DecisionReply.decided_by 保留人工通道且未改原有四值", () => {
  const values = decidedByEnum();
  assert.deepEqual(values, ["jev_api", "llm_fallback", "rule_fallback", "cache", "human"], "人工层枚举必须存在，且不得改语义或删值");
  const mirror = read("src/shared/src/types.ts");
  assert.match(mirror, /export type DecidedBy =[^;]*"human"/, "TS 镜像必须同步 human（只追加）");
  const openapi = read("contracts/openapi.yaml");
  const line = openapi.split("\n").find((l) => l.includes("decided_by:"));
  assert.ok(line && line.includes("human") && line.includes("jev_api"), "OpenAPI 枚举必须与 schema 一致");
});

test("human 样例通过运行时校验，未知通道必被拒，原样例保持兼容", () => {
  const schema = parse("contracts/schemas/DecisionReply.json") as Parameters<typeof validateInstance>[1];
  const human = parse("fixtures/decisionreply.human.sample.json") as DecisionReply;
  assert.deepEqual(validateInstance(human, schema), [], "human 样例必须通过契约校验");
  assert.equal(human.decided_by, "human");
  const tampered = { ...human, decided_by: "not_a_channel" as DecisionReply["decided_by"] };
  assert.ok(validateInstance(tampered, schema).length > 0, "未知通道必须被拒");
  const legacy = parse("fixtures/decisionreply.sample.json");
  assert.deepEqual(validateInstance(legacy, schema), [], "原有样例仍须通过（向后兼容）");
});

test("CHANGELOG v1.1.0 已登记人工通道影响面", () => {
  const log = read("contracts/schemas/CHANGELOG.md");
  assert.match(log, /## v1\.1\.0/, "契约增量必须入 CHANGELOG");
  assert.match(log, /DecisionReply[\s\S]*?decided_by[\s\S]*?human/, "影响面须写明字段与新增值");
});
