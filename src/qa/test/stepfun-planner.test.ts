import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { classifyIntent } from "../src/q1-intent.js";
import { MemoryIndex, readFixtureChunks } from "../src/q2-retrieval.js";
import { refineQ1WithStepFun, rewriteQ2WithStepFun, shouldRewriteQ2WithStepFun } from "../src/stepfun-planner.js";
import type { StepFunPlannerOptions } from "../src/stepfun-planner.js";
import type { StepFunChatClient } from "../src/stepfun-answerer.js";

function turn(text: string) { return { session_id: "s_planner", turn_id: "t_planner", text }; }
async function evidenceFor(question: string) {
  const plan = classifyIntent(turn(question));
  const index = new MemoryIndex();
  index.upsert(readFixtureChunks());
  const evidence = await index.search({ query_id: "q_planner", query_text: plan.rewrite_text, top_k: 5, trace_id: "tr_planner", schema_version: "1.0" });
  return { plan, evidence, index };
}
function reply(text: string) { return { provider: "stepplan", model_id: "step-3.7-flash", degraded_to: "", text }; }
function options(over: Partial<StepFunPlannerOptions> = {}): StepFunPlannerOptions {
  return { provider: "stepplan", modelId: "step-3.7-flash", apiKeyConfigured: true, ...over, traceId: over.traceId ?? "tr_planner_default" };
}

test("Q1 StepPlan only runs on low-confidence text and never invents slots", async () => {
  const question = "你能帮我看看这个漏洞吗？";
  const { plan } = await evidenceFor(question);
  assert.equal(plan.needs_clarify, true);
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const client: StepFunChatClient = { chat: async (_role, _messages, _params, _trace, _domain) => reply(JSON.stringify({ intent: "remediation", clarify_question: null })) };
  const result = await refineQ1WithStepFun(question, plan, options({ client, bus, traceId: "tr_planner" }));
  assert.equal(result.used_llm, true);
  assert.equal(result.plan.classifier_source, "stepplan");
  assert.deepEqual(result.plan.intents, ["remediation"]);
  assert.equal(result.plan.needs_clarify, false);
  assert.deepEqual(result.plan.slots, plan.slots, "StepPlan must not invent slots");
  assert.ok((await store.readLineage("tr_planner")).some(row => row.stage === "qa.q1_stepfun" && row.status === "success"));
});

test("Q1 StepPlan abstains safely and keeps a validated clarifying question", async () => {
  const question = "说说这个漏洞的情况";
  const { plan } = await evidenceFor(question);
  const clarifier = "你更想了解影响范围还是修复方式？";
  const client: StepFunChatClient = { chat: async () => reply(JSON.stringify({ intent: "uncertain", confidence: 0.35, clarify_question: clarifier })) };
  const result = await refineQ1WithStepFun(question, plan, options({ client, traceId: "tr_planner_uncertain" }));
  assert.equal(result.used_llm, true);
  assert.equal(result.plan.needs_clarify, true);
  assert.equal(result.plan.clarify_question, clarifier);
});

test("Q1 does not call StepPlan for a tiny ambiguous utterance", async () => {
  const plan = classifyIntent(turn("嗯"));
  let calls = 0;
  const client: StepFunChatClient = { chat: async () => { calls++; return reply("{}"); } };
  const result = await refineQ1WithStepFun("嗯", plan, options({ client, traceId: "tr_planner_short" }));
  assert.equal(calls, 0);
  assert.equal(result.attempted, false);
  assert.equal(result.plan.needs_clarify, true);
});

test("Q2 StepPlan only rewrites empty retrieval and keeps evidence from the retriever", async () => {
  const question = "CVE-2021-44228 影响哪些版本？";
  const { plan, evidence } = await evidenceFor(question);
  const empty = { ...evidence, chunks: [] };
  let prompt = "";
  let searched = "";
  const client: StepFunChatClient = { chat: async (_role, messages) => { prompt = messages[1]?.content ?? ""; return reply(JSON.stringify({ query: "CVE-2021-44228 Log4j2 affected versions" })); } };
  const result = await rewriteQ2WithStepFun(question, plan, empty, options({ client, traceId: "tr_planner_q2" }), async (query) => { searched = query; return evidence; });
  assert.equal(result.used_llm, true);
  assert.equal(searched, "CVE-2021-44228 Log4j2 affected versions");
  assert.ok(!prompt.includes(evidence.chunks[0]?.text ?? "fixture sentinel"), "raw source text must not be sent to the planner");
  assert.deepEqual(result.retrieval.chunks.map(chunk => chunk.chunk_id), evidence.chunks.map(chunk => chunk.chunk_id));
});

test("Q2 rejects invented CVE identifiers and retains original retrieval", async () => {
  const question = "CVE-2021-44228 影响哪些版本？";
  const { plan, evidence } = await evidenceFor(question);
  const empty = { ...evidence, chunks: [] };
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const client: StepFunChatClient = { chat: async () => reply(JSON.stringify({ query: "CVE-2099-9999 affected versions" })) };
  const result = await rewriteQ2WithStepFun(question, plan, empty, options({ client, bus, traceId: "tr_planner_bad_rewrite" }), async () => evidence);
  assert.equal(result.used_llm, false);
  assert.equal(result.retrieval.chunks.length, 0);
  assert.match(result.fallback_reason ?? "", /改写未通过 CVE/);
  const events = await store.read<{ user_visible: boolean }>("fallback.events");
  assert.equal(events.length, 1);
  assert.equal(events[0]?.payload.user_visible, true);
});

test("Q1 missing key records visible fallback and never calls the client", async () => {
  const question = "说说这个漏洞的情况";
  const plan = classifyIntent(turn(question));
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  let calls = 0;
  const client: StepFunChatClient = { chat: async () => { calls++; return reply("{}"); } };
  const result = await refineQ1WithStepFun(question, plan, options({ apiKeyConfigured: false, client, bus, traceId: "tr_planner_no_key" }));
  assert.equal(result.used_llm, false);
  assert.equal(result.plan.needs_clarify, true);
  assert.equal(calls, 0);
  const events = await store.read<{ user_visible: boolean }>("fallback.events");
  assert.equal(events.length, 1);
  assert.equal(events[0]?.payload.user_visible, true);
});

test("Q2 rewrites only when retrieval coverage is weak for the selected strategy", async () => {
  const { plan, evidence } = await evidenceFor("CVE-2021-44228 影响哪些版本？");
  assert.equal(shouldRewriteQ2WithStepFun(plan, evidence), false, "adequate fact lookup stays on rules/retriever");
  const multiHop = { ...plan, strategy: "multi_hop" as const };
  assert.equal(shouldRewriteQ2WithStepFun(multiHop, { ...evidence, chunks: evidence.chunks.slice(0, 1) }), true);
  assert.equal(shouldRewriteQ2WithStepFun(plan, { ...evidence, chunks: [] }), true);
});