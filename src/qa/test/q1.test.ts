import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classifyIntent } from "../src/q1-intent.js";
import type { QueryTurn } from "@safetrace/shared";
import type { IntentKind } from "../src/q1-intent.js";

interface GoldenCase {
  qid: string;
  text: string;
  expected_intent: IntentKind;
  expect_abstain?: boolean;
  notes?: string;
}

function loadGolden(): GoldenCase[] {
  const raw = JSON.parse(
    readFileSync(new URL("../../../fixtures/golden-qa.v0.json", import.meta.url), "utf8"),
  ) as { cases: GoldenCase[] };
  return raw.cases;
}

function turn(text: string): QueryTurn {
  return { session_id: "sess_t", turn_id: "turn_t", text };
}

test("Q1：golden-qa.v0.json 十条逐一断言意图", () => {
  const cases = loadGolden();
  assert.equal(cases.length, 10);
  for (const c of cases) {
    const plan = classifyIntent(turn(c.text));
    assert.equal(plan.intents[0], c.expected_intent, c.qid + " 主意图应为 " + c.expected_intent);
    assert.ok(plan.intents.includes(c.expected_intent), c.qid + " intents 应包含 " + c.expected_intent);
    assert.equal(plan.needs_clarify, false, c.qid + " 不应要求澄清");
    assert.ok(plan.confidence > 0, c.qid + " 置信度应 > 0");
    if (c.expect_abstain) {
      // 无答案基准：Q1 仍应正确路由并抽出 CVE 槽位；abstain 由 q2/q4 测试验证
      assert.deepEqual(plan.slots.cve_ids, ["CVE-2099-4321"], c.qid + " 应抽出 CVE 槽位");
    }
  }
});

test("Q1：黄金集覆盖度（impact_range×2 / remediation×2 / concept / attack_chain / trend / paper_related / abstain×1）", () => {
  const cases = loadGolden();
  const need: Record<string, number> = { impact_range: 2, remediation: 2, concept: 1, attack_chain: 1, trend: 1 };
  const byIntent = new Map<string, number>();
  for (const c of cases) {
    const plan = classifyIntent(turn(c.text));
    assert.equal(plan.intents[0], c.expected_intent, c.qid + " 分类应自洽");
    byIntent.set(c.expected_intent, (byIntent.get(c.expected_intent) ?? 0) + 1);
  }
  for (const [k, n] of Object.entries(need)) {
    assert.ok((byIntent.get(k) ?? 0) >= n, "意图 " + k + " 至少 " + n + " 条");
  }
  assert.ok((byIntent.get("paper_related") ?? 0) >= 1, "至少一条 paper_related");
  assert.ok(cases.filter((c) => c.expect_abstain === true).length >= 1, "至少一条 abstain 基准");
});

test("Q1：槽位抽取（CVE / 产品 / 版本 / 时间窗 / 策略）", () => {
  const plan = classifyIntent(
    turn("CVE-2021-44228 和 CVE-2022-22965 影响哪些版本？log4j 2.14.1 与 spring 怎么修复，最近一年的趋势？"),
  );
  assert.deepEqual(plan.slots.cve_ids, ["CVE-2021-44228", "CVE-2022-22965"]);
  assert.ok(plan.slots.products.includes("log4j"));
  assert.ok(plan.slots.products.includes("spring"));
  assert.ok(plan.slots.versions.includes("2.14.1"));
  assert.equal(plan.slots.time_range, "1y");
  assert.equal(plan.strategy, "multi_hop"); // 多 CVE → multi_hop
  assert.ok(plan.rewrite_text.includes("CVE-2021-44228"));
  assert.ok(plan.rewrite_text.includes("product=log4j"));
});

test("Q1：rewrite_text 携带槽位补全后缀", () => {
  const plan = classifyIntent(turn("CVE-2021-44228 影响哪些版本？"));
  assert.ok(plan.rewrite_text.includes("CVE=CVE-2021-44228"), plan.rewrite_text);
  assert.ok(plan.rewrite_text.includes("槽位补全"));
});

test("Q1：低置信度 → needs_clarify 且给出澄清问题（禁止硬猜）", () => {
  const plan = classifyIntent(turn("嗯"));
  assert.equal(plan.needs_clarify, true);
  assert.ok((plan.clarify_question ?? "").length > 0);
  assert.deepEqual(plan.intents, []);
  assert.equal(plan.confidence, 0);
});

test("Q1：时间窗归一（7d / 30d / ytd / null）", () => {
  assert.equal(classifyIntent(turn("最近一周的漏洞趋势")).slots.time_range, "7d");
  assert.equal(classifyIntent(turn("近一个月的热点")).slots.time_range, "30d");
  assert.equal(classifyIntent(turn("今年有多少漏洞")).slots.time_range, "ytd");
  assert.equal(classifyIntent(turn("漏洞趋势")).slots.time_range, null);
});
