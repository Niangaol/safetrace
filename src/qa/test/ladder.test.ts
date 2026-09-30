/**
 * A-02 验收：四层兜底阶梯。
 * 关键断言：逐层显式下坠、LLM 低置信度弃权才下坠、decision.replies 全量入总线可 replay、
 * escalation_trace 完整留痕、全链未决时明确挂起而不伪造决策。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest, FallbackEvent } from "@safetrace/shared";
import { runDecisionLadder } from "../src/ladder/decision-ladder.js";

function req(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    decision_id: "dec_1",
    kind: "q1_route",
    state: { question: "影响哪些版本？" },
    questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
    trace_id: "tr_ladder",
    schema_version: "1.0",
    ...over,
  };
}

test("工具层命中：不下坠，decided_by 如实记 rule_fallback", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(req(), {
    bus,
    tool: async () => ({ choice: "impact_range", score: 1 }),
    rule: async () => ({ choice: "should-not-reach" }),
  });
  assert.equal(res.reply.decided_by, "rule_fallback");
  assert.equal(res.reply.decision.choice, "impact_range");
  assert.equal(res.escalated, false, "工具层命中不应标记下坠");
  assert.deepEqual(res.escalation_trace.map((a) => a.layer), ["tool"]);
  assert.equal(res.reply.fallback_reason, undefined, "无下坠则不写 fallback_reason");
});

test("工具缺失 → 规则命中：显式下坠且留痕", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(req(), {
    bus,
    rule: async () => ({ choice: "remediation", score: 0.8 }),
  });
  assert.equal(res.reply.decided_by, "rule_fallback");
  assert.equal(res.escalated, true);
  const toolStep = res.escalation_trace.find((a) => a.layer === "tool")!;
  assert.equal(toolStep.status, "unavailable", "缺失必须显式记录，不得静默跳过");
  assert.match(res.reply.fallback_reason ?? "", /tool:tool 层未接入/);
  // 每次下坠都登记 FallbackEvent
  const falls = await store.read<FallbackEvent>("fallback.events");
  assert.ok(falls.some((e) => e.payload.degraded_of === "ladder:tool"), "下坠必须落 FallbackEvent");
});

test("LLM 低置信度弃权 → 下坠人工层；decided_by=llm_fallback", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(req(), {
    bus,
    rule: async () => null, // 规则层也弃权
    llm: async () => ({ choice: "impact_range", score: 0.62 }),
  });
  assert.equal(res.reply.decided_by, "llm_fallback");
  assert.equal(res.reply.decision.score, 0.62);
  assert.equal(res.escalated, true);
  const llmStep = res.escalation_trace.find((a) => a.layer === "llm")!;
  assert.equal(llmStep.status, "success");
  const ruleStep = res.escalation_trace.find((a) => a.layer === "rule")!;
  assert.equal(ruleStep.status, "abstained", "规则弃权必须显式记录");
});

test("LLM 弃权（返回 null）→ 继续下坠到人工层，decided_by 如实记 human", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(req(), {
    bus,
    llm: async () => null,
    human: async () => ({ choice: "impact_range", score: 0.5 }),
  });
  assert.equal(res.reply.decided_by, "human", "人工层必须记 human，不得冒充 rule_fallback");
  assert.equal(res.reply.decision.choice, "impact_range");
  assert.deepEqual(res.escalation_trace.map((a) => a.layer), ["tool", "rule", "llm", "human"]);
  const falls = await store.read<FallbackEvent>("fallback.events");
  assert.ok(falls.some((e) => e.payload.degraded_of === "ladder:llm"), "LLM 弃权必须留 FallbackEvent");
});

test("全链未决且无人工队列：明确挂起，abstained=true 且不伪造 choice", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(req(), { bus });
  assert.equal(res.reply.decided_by, "human");
  assert.equal(res.reply.decision.abstain, true);
  assert.equal(res.reply.calibrated_prob, 0);
  assert.equal(res.escalated, true);
  const layers = res.escalation_trace.map((a) => a.layer);
  assert.deepEqual(layers, ["tool", "rule", "llm", "human"]);
  for (const step of res.escalation_trace) {
    assert.notEqual(step.status, "success", "未接入层必须是 unavailable/failed，不得伪造成功");
  }
  const replies = await store.read("decision.replies");
  assert.equal(replies.length, 1, "reply 必须入总线可 replay");
});

test("decision.replies 全量入总线：每次阶梯结束恰好一条", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  await runDecisionLadder(req({ decision_id: "d1" }), { bus, rule: async () => ({ choice: "a" }) });
  await runDecisionLadder(req({ decision_id: "d2" }), { bus });
  const replies = await store.read("decision.replies");
  assert.equal(replies.length, 2);
  assert.deepEqual(replies.map((r) => (r.payload as DecisionReply).decision_id).sort(), ["d1", "d2"]);
});
