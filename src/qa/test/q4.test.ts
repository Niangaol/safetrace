import { test } from "node:test";
import assert from "node:assert/strict";
import type { EvidenceChunk, RetrievalResponse } from "@safetrace/shared";
import { classifyIntent } from "../src/q1-intent.js";
import { MemoryIndex, readFixtureChunks } from "../src/q2-retrieval.js";
import { ABSTAIN_RERANK_FLOOR, synthesizeAnswer } from "../src/q4-answer.js";
import type { AnswerSynthesizer } from "../src/q4-answer.js";

function turn(text: string) {
  return { session_id: "sess_t", turn_id: "turn_t", text };
}

function makeChunk(id: string, over: Partial<EvidenceChunk> = {}): EvidenceChunk {
  return {
    chunk_id: id,
    doc_type: "vuln_advisory",
    text: "CVE-2021-44228（Log4Shell）：Apache Log4j2 2.0-beta9 至 2.15.0 受影响，2.15.0 修复。",
    quality_score: 0.9,
    provenance: {
      url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      section: "description",
    },
    ...over,
  };
}

function makeEvidence(chunks: EvidenceChunk[], over: Partial<RetrievalResponse> = {}): RetrievalResponse {
  return {
    query_id: "q_t",
    chunks,
    retrieval_ms: 1,
    embedder_model_id: "bm25-lite-v1",
    trace_id: "tr_t",
    schema_version: "1.0",
    ...over,
  };
}

function scored(chunks: EvidenceChunk[], first = 0.95): EvidenceChunk[] {
  return chunks.map((c, i) => ({ ...c, score_dense: 0.8, score_rerank: Math.max(0.05, first - i * 0.1) }));
}

test("Q4：引用完整率 100%（每条 citation 有 chunk_id + url，正文角标一一对应）", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const chunks = scored([
    makeChunk("chunk_a"),
    makeChunk("chunk_b", { doc_type: "enrichment", text: "CVSS v3.1 基础分 10.0，EPSS 0.97。" }),
    makeChunk("chunk_c", { doc_type: "paper", text: "论文：Log4Shell 大规模利用分析。" }),
  ]);
  const evidence = makeEvidence(chunks);
  const ans = await synthesizeAnswer(question, plan, evidence, { session_id: "s1", turn_id: "t1" });

  assert.equal(ans.abstained, false);
  assert.equal(ans.citations.length, evidence.chunks.length);
  ans.citations.forEach((cit, i) => {
    assert.ok(cit.chunk_id.length > 0, "citation.chunk_id 不得为空");
    assert.match(cit.url, /^https?:\/\//, "citation.url 必须可回溯");
    assert.equal(cit.chunk_id, chunks[i]!.chunk_id, "citations 与 chunks 顺序一一对应");
    assert.ok(ans.text_md.includes("[" + (i + 1) + "]"), "正文应含角标 [" + (i + 1) + "]");
  });
  // 四段式
  assert.ok(ans.text_md.includes("## 结论"));
  assert.ok(ans.text_md.includes("## 证据"));
  assert.ok(ans.text_md.includes("## 推理链"));
  assert.ok(ans.text_md.includes("## 置信度"));
  assert.ok(ans.confidence > 0 && ans.confidence <= 1);
  assert.ok(ans.reasoning_chain.length >= 3);
  assert.equal(ans.session_id, "s1");
  assert.equal(ans.turn_id, "t1");
});

test("Q4：citations 与 chunk_id / provenance.url 严格一致", async () => {
  const question = "CVE-2021-44228 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const chunks = scored([makeChunk("chunk_a"), makeChunk("chunk_b")]);
  const ans = await synthesizeAnswer(question, plan, makeEvidence(chunks));
  assert.deepEqual(ans.citations.map((c) => c.chunk_id), chunks.map((c) => c.chunk_id));
  assert.deepEqual(ans.citations.map((c) => c.url), chunks.map((c) => c.provenance.url));
});

test("Q4：abstain —— 证据为空", async () => {
  const question = "CVE-2099-4321 应该怎么修复？";
  const plan = classifyIntent(turn(question));
  const ans = await synthesizeAnswer(question, plan, makeEvidence([]));
  assert.equal(ans.abstained, true);
  assert.deepEqual(ans.citations, []);
  assert.equal(ans.confidence, 0);
  assert.ok(ans.text_md.includes("证据不足"), "文案必须显式说明证据不足");
  assert.ok(ans.text_md.includes("禁止编造"));
});

test("Q4：abstain —— 最高 score_rerank 低于阈值", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const chunks = [makeChunk("chunk_low", { score_rerank: ABSTAIN_RERANK_FLOOR - 0.01, score_dense: 0.1 })];
  const ans = await synthesizeAnswer(question, plan, makeEvidence(chunks));
  assert.equal(ans.abstained, true);
  assert.ok(ans.text_md.includes("低于阈值"));
  assert.deepEqual(ans.citations, []);
});

test("Q4：没有 reranker 时使用最高可用 dense/sparse 分数", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const chunks = [makeChunk("chunk_sparse", { score_dense: 0.15, score_sparse: 0.82 })];
  const answer = await synthesizeAnswer(question, plan, makeEvidence(chunks));
  assert.equal(answer.abstained, false, "高 BM25 分数不应被较低的 dense 分数遮蔽");
});

test("Q4：abstain —— 证据不覆盖问题指定的 CVE（答非所问拒答）", async () => {
  const question = "CVE-2099-4321 应该怎么修复？";
  const plan = classifyIntent(turn(question));
  const chunks = scored([makeChunk("chunk_other"), makeChunk("chunk_other2")]);
  const ans = await synthesizeAnswer(question, plan, makeEvidence(chunks));
  assert.equal(ans.abstained, true);
  assert.ok(ans.text_md.includes("CVE-2099-4321"));
});

test("Q4：abstain —— Q1 低置信度需澄清时拒答并给出澄清问题", async () => {
  const plan = classifyIntent(turn("嗯"));
  assert.equal(plan.needs_clarify, true);
  const ans = await synthesizeAnswer("嗯", plan, makeEvidence(scored([makeChunk("chunk_a")])));
  assert.equal(ans.abstained, true);
  assert.ok(ans.text_md.includes(plan.clarify_question ?? "@@missing@@"));
});

test("Q4：degraded_to 透传 + 用户可见降级提示", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const ans = await synthesizeAnswer(question, plan, makeEvidence(scored([makeChunk("chunk_a")]), { degraded_to: "memory_index" }));
  assert.equal(ans.abstained, false);
  assert.equal(ans.degraded_to, "memory_index");
  assert.ok(ans.text_md.includes("memory_index"), "答案尾部必须给用户可见的降级提示");
});

test("Q4：注入式合成器可替换默认模板（MG1 接线点）", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const evidence = makeEvidence(scored([makeChunk("chunk_a", { trust: "trusted" })]));
  const synth: AnswerSynthesizer = {
    synthesize: async () => ({
      session_id: "s_mg1",
      turn_id: "t_mg1",
      text_md: "MG1 stub answer",
      citations: [{ chunk_id: "chunk_a", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }],
      reasoning_chain: ["stub"],
      confidence: 0.42,
      abstained: false,
    }),
  };
  const ans = await synthesizeAnswer(question, plan, evidence, { synth });
  assert.equal(ans.text_md, "MG1 stub answer");
  assert.equal(ans.confidence, 0.42);
});

test("Q4：直接注入的云合成器不能绕过 A-04 出云闸", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent(turn(question));
  const evidence = makeEvidence(scored([makeChunk("chunk_safe", { trust: "trusted" })]));
  const store = new (await import("@safetrace/shared")).MemoryEventStore();
  const bus = new (await import("@safetrace/shared")).EventBus({ store });
  let calls = 0;
  const synth: AnswerSynthesizer = { synthesize: async () => { calls++; throw new Error("must not call"); } };
  const answer = await synthesizeAnswer(question, plan, evidence, {
    bus, synth, synthesizer: { provider: "stepplan", model_id: "step-3.7-flash" },
    injectionGuard: { screened: false, note: "upstream screen unavailable" },
  });
  assert.equal(calls, 0);
  assert.equal(answer.degraded_to, "template");
  assert.match(answer.text_md, /没有发送到云端/);
  const fallbacks = await store.read<{ user_visible: boolean }>("fallback.events");
  assert.equal(fallbacks.length, 1);
  assert.equal(fallbacks[0]?.payload.user_visible, true);
});

test("Q4：外部合成器不能绕过澄清/证据门禁", async () => {
  const question = "嗯";
  const plan = classifyIntent(turn(question));
  const evidence = makeEvidence(scored([makeChunk("chunk_a", { trust: "trusted" })]));
  let calls = 0;
  const synth: AnswerSynthesizer = { synthesize: async () => { calls++; throw new Error("must not call"); } };
  const answer = await synthesizeAnswer(question, plan, evidence, {
    synth, synthesizer: { provider: "stepplan", model_id: "step-3.7-flash" },
  });
  assert.equal(calls, 0);
  assert.equal(answer.abstained, true);
  assert.ok(answer.text_md.includes(plan.clarify_question ?? "@@missing@@"));
});

test("Q4 端到端：Q1→Q2→Q4，Log4Shell 有答案 / CVE-2099 拒答", async () => {
  const engine = new MemoryIndex();
  engine.upsert(readFixtureChunks());

  const q1 = "Log4Shell 影响哪些版本？怎么修复？";
  const plan1 = classifyIntent(turn(q1));
  const ev1 = await engine.search({
    query_id: "q_e2e",
    query_text: plan1.rewrite_text,
    top_k: 5,
    trace_id: "tr_e2e",
    schema_version: "1.0",
  });
  const ans1 = await synthesizeAnswer(q1, plan1, ev1);
  assert.equal(ans1.abstained, false);
  assert.ok(ans1.citations.length >= 3);
  assert.ok(ans1.text_md.includes("2.15.0"));

  const q2 = "CVE-2099-4321 应该怎么修复？";
  const plan2 = classifyIntent(turn(q2));
  const ev2 = await engine.search({
    query_id: "q_e2e2",
    query_text: plan2.rewrite_text,
    top_k: 5,
    cve_ids: plan2.slots.cve_ids,
    trace_id: "tr_e2e",
    schema_version: "1.0",
  });
  const ans2 = await synthesizeAnswer(q2, plan2, ev2);
  assert.equal(ans2.abstained, true);
  assert.equal(ans2.citations.length, 0);
});
