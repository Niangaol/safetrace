import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classifyIntent } from "../src/q1-intent.js";
import type { QueryTurn } from "@safetrace/shared";
import type { IntentKind } from "../src/q1-intent.js";

interface GoldenCase {
  qid: string;
  text: string;
  /** 澄清类（expects_clarify）不标注主意图 */
  expected_intent?: IntentKind;
  expects_clarify?: boolean;
  expect_abstain?: boolean;
  /** Q1 槽位硬断言：问题文本应抽出的 CVE 列表（R-04） */
  expected_cve_ids?: string[];
  /** 非拒答条答案必含要素（Q4 text_md 子串，R-04，冒烟同口径断言） */
  expected_answer_must_include?: string[];
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

test("Q1：golden-qa.v0.json 二十条逐一断言意图与 cve_ids 槽位", () => {
  const cases = loadGolden();
  assert.equal(cases.length, 20, "R-04：黄金集扩到 20 条");
  for (const c of cases) {
    const plan = classifyIntent(turn(c.text));
    if (c.expects_clarify) {
      // 澄清基准：低置信度必须显式澄清，禁止硬猜
      assert.equal(plan.needs_clarify, true, c.qid + " 低置信度应要求澄清");
      assert.deepEqual(plan.intents, [], c.qid + " 澄清时不应给出意图");
      assert.equal(plan.confidence, 0, c.qid + " 澄清时置信度为 0");
    } else {
      assert.equal(plan.intents[0], c.expected_intent, c.qid + " 主意图应为 " + c.expected_intent);
      assert.ok(plan.intents.includes(c.expected_intent!), c.qid + " intents 应包含 " + c.expected_intent);
      assert.equal(plan.needs_clarify, false, c.qid + " 不应要求澄清");
      assert.ok(plan.confidence > 0, c.qid + " 置信度应 > 0");
    }
    // R-04：cve_ids 槽位硬断言（无答案基准同样要正确抽出槽位，abstain 由 q2/q4 验证）
    assert.deepEqual(plan.slots.cve_ids, c.expected_cve_ids ?? [], c.qid + " cve_ids 槽位应匹配");
  }
});

test("Q1：黄金集覆盖度（6 类意图 + 拒答 + 澄清，共 20 条）", () => {
  const cases = loadGolden();
  const need: Record<string, number> = { impact_range: 2, remediation: 2, concept: 1, attack_chain: 1, trend: 1 };
  const byIntent = new Map<string, number>();
  for (const c of cases) {
    if (c.expects_clarify) continue; // 澄清类不计入意图分布
    const plan = classifyIntent(turn(c.text));
    assert.equal(plan.intents[0], c.expected_intent, c.qid + " 分类应自洽");
    byIntent.set(c.expected_intent!, (byIntent.get(c.expected_intent!) ?? 0) + 1);
  }
  for (const [k, n] of Object.entries(need)) {
    assert.ok((byIntent.get(k) ?? 0) >= n, "意图 " + k + " 至少 " + n + " 条");
  }
  assert.ok((byIntent.get("paper_related") ?? 0) >= 1, "至少一条 paper_related");
  assert.ok(cases.filter((c) => c.expect_abstain === true).length >= 3, "至少三条 abstain 基准");
  assert.ok(cases.filter((c) => c.expects_clarify === true).length >= 1, "至少一条澄清基准");
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
