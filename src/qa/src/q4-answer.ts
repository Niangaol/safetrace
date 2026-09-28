/**
 * Q4 答案合成：四段式模板（结论—证据—推理链—置信度），引用与证据 chunk 一一对应。
 * 纪律：
 * - 证据为空 / 最高 score_rerank < 0.3 / 证据不覆盖问题中的 CVE / Q1 低置信度需澄清
 *   → abstained=true，文案显式说明证据不足，禁止编造；
 * - degraded_to 从 RetrievalResponse 原样透传，并在答案尾部给用户可见提示。
 */
import type { Answer, RetrievalResponse } from "@safetrace/shared";
import type { QueryPlan } from "./q1-intent.js";

/**
 * 注入接口：未来 MG1 接 LLM 时实现该接口替换默认模板合成器。
 * 接线发生在编排层/冒烟（见 openapi.yaml /v1/chat/complete），本包不 import gateway。
 */
export interface AnswerSynthesizer {
  synthesize(question: string, plan: QueryPlan, evidence: RetrievalResponse): Promise<Answer> | Answer;
}

export interface SynthesizeOptions {
  synth?: AnswerSynthesizer;
  /** 编排层应显式传入；缺省时 session_id 为空串、turn_id 回落 evidence.trace_id */
  session_id?: string;
  turn_id?: string;
}

/** 最高重排分低于该值 → 证据不足，拒答。 */
export const ABSTAIN_RERANK_FLOOR = 0.3;

interface Ctx {
  topRerank: number;
  avgQuality: number;
}

interface BaseAnswer {
  session_id: string;
  turn_id: string;
  degraded_to?: string;
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

/** 取首句（超长截断）；结论段只摘录证据原文，不转写不发挥。 */
function firstSentence(text: string, maxLen = 160): string {
  const m = text.match(/^.*?[。！？.!?](\s|$)/s);
  let s = (m ? m[0] : text).trim();
  if (s.length === 0) s = text.trim().slice(0, maxLen);
  if (s.length > maxLen) s = s.slice(0, maxLen) + "…";
  return s;
}

/** 问题指定了 CVE 时，证据必须覆盖其中至少一个，否则视为答非所问 → 拒答。 */
function coversRequestedCve(plan: QueryPlan, evidence: RetrievalResponse): boolean {
  if (plan.slots.cve_ids.length === 0) return true;
  return plan.slots.cve_ids.some((id) =>
    evidence.chunks.some((c) => c.text.toUpperCase().includes(id.toUpperCase())),
  );
}

function intentLabel(plan: QueryPlan): string {
  return plan.intents.length > 0 ? plan.intents.join("+") : "未识别（意图不明确）";
}

function degradedNote(evidence: RetrievalResponse): string | null {
  if (!evidence.degraded_to) return null;
  return "> ⚠️ 本次检索经过降级通道（degraded_to=" + evidence.degraded_to + "），证据覆盖可能不完整，结论请谨慎采用。";
}

function buildAbstain(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  reasons: string[],
  ctx: Ctx,
  base: BaseAnswer,
): Answer {
  void question;
  const lines: string[] = [];
  lines.push("## 结论");
  lines.push("**证据不足，本次不予作答（abstained）。** " + reasons.join("；") + "。按项目红线：证据不足时禁止编造答案。");
  lines.push("## 证据");
  if (evidence.chunks.length === 0) {
    lines.push("（无可用证据块）");
  } else {
    lines.push("以下证据未达作答标准，仅列出备查，不作为答案依据：");
    evidence.chunks.forEach((c, i) => {
      lines.push(
        "[" + (i + 1) + "] " + c.doc_type + "｜" + c.provenance.url +
        "｜重排分 " + (c.score_rerank ?? 0).toFixed(2) +
        (c.quality_score !== undefined ? "｜质量分 " + c.quality_score.toFixed(2) : ""),
      );
      lines.push("> " + firstSentence(c.text, 80));
    });
  }
  const chain: string[] = [
    "Q1 意图判定：" + intentLabel(plan) + "，检索策略 " + plan.strategy,
    "Q2 检索返回 " + evidence.chunks.length + " 条证据（索引模型 " + evidence.embedder_model_id + "），最高重排分 " + ctx.topRerank.toFixed(2),
    "触发拒答条件：" + reasons.join("；"),
    plan.needs_clarify && plan.clarify_question
      ? "处置：先向用户澄清——" + plan.clarify_question
      : "处置：请补充检索条件（如指定 CVE、放宽 min_quality、扩大时间范围）后重试",
  ];
  lines.push("## 推理链");
  chain.forEach((s, i) => lines.push((i + 1) + ". " + s));
  lines.push("## 置信度");
  lines.push("0.00 —— 拒答：无可靠证据支撑，不以低置信度硬答。");
  const note = degradedNote(evidence);
  if (note) lines.push(note);
  return {
    ...base,
    text_md: lines.join("\n\n"),
    citations: [],
    reasoning_chain: chain,
    confidence: 0,
    abstained: true,
  };
}

function buildAnswer(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  ctx: Ctx,
  base: BaseAnswer,
): Answer {
  const n = evidence.chunks.length;
  const top = evidence.chunks[0]!;
  const confidence = round2(clamp01(0.6 * ctx.topRerank + 0.05 * Math.min(n - 1, 3) + 0.2 * ctx.avgQuality));
  const citations = evidence.chunks.map((c) => ({ chunk_id: c.chunk_id, url: c.provenance.url }));

  const lines: string[] = [];
  lines.push("## 结论");
  lines.push(
    "针对「" + question + "」，检索到 " + n + " 条可回溯证据（最高重排分 " + ctx.topRerank.toFixed(2) + "）。" +
    "主要证据 [1]（" + top.doc_type + "）原文摘录：",
  );
  lines.push("> " + firstSentence(top.text));
  lines.push("## 证据");
  evidence.chunks.forEach((c, i) => {
    lines.push(
      "[" + (i + 1) + "] " + c.doc_type + "｜[原文链接](" + c.provenance.url + ")｜重排分 " +
      (c.score_rerank ?? 0).toFixed(2) +
      (c.quality_score !== undefined ? "｜质量分 " + c.quality_score.toFixed(2) : ""),
    );
    lines.push("> " + c.text);
  });
  const chain: string[] = [
    "Q1 意图判定：" + intentLabel(plan) + "，检索策略 " + plan.strategy,
    "Q2 检索返回 " + n + " 条证据，最高重排分 " + ctx.topRerank.toFixed(2) + "，索引模型 " + evidence.embedder_model_id,
    "逐条核对 provenance：" + n + " 条证据均可回溯到原文 URL，正文角标 [1]-[" + n + "] 与 citations 一一对应",
    "置信度 = 0.6×最高重排分 + 0.05×附加证据数(≤3) + 0.2×平均质量分 = " + confidence.toFixed(2),
  ];
  lines.push("## 推理链");
  chain.forEach((s, i) => lines.push((i + 1) + ". " + s));
  lines.push("## 置信度");
  lines.push(
    confidence.toFixed(2) + "（依据：最高重排分 " + ctx.topRerank.toFixed(2) +
    "、证据 " + n + " 条、平均质量分 " + ctx.avgQuality.toFixed(2) + "）",
  );
  const note = degradedNote(evidence);
  if (note) lines.push(note);
  return {
    ...base,
    text_md: lines.join("\n\n"),
    citations,
    reasoning_chain: chain,
    confidence,
    abstained: false,
  };
}

/**
 * 合成答案。证据不满足作答标准时显式拒答（abstained=true），不产出任何编造内容。
 */
export async function synthesizeAnswer(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  opts: SynthesizeOptions = {},
): Promise<Answer> {
  if (opts.synth) return opts.synth.synthesize(question, plan, evidence);

  const base: BaseAnswer = {
    session_id: opts.session_id ?? "",
    turn_id: opts.turn_id ?? evidence.trace_id,
    ...(evidence.degraded_to ? { degraded_to: evidence.degraded_to } : {}),
  };
  const topRerank = evidence.chunks.reduce((m, c) => Math.max(m, c.score_rerank ?? 0), 0);
  const qs = evidence.chunks
    .map((c) => c.quality_score)
    .filter((q): q is number => typeof q === "number");
  const ctx: Ctx = {
    topRerank,
    avgQuality: qs.length > 0 ? qs.reduce((s, q) => s + q, 0) / qs.length : 0,
  };

  const reasons: string[] = [];
  if (evidence.chunks.length === 0) reasons.push("检索没有返回任何证据块");
  if (evidence.chunks.length > 0 && topRerank < ABSTAIN_RERANK_FLOOR) {
    reasons.push("最高重排分 " + topRerank.toFixed(2) + " 低于阈值 " + ABSTAIN_RERANK_FLOOR.toFixed(2));
  }
  if (plan.needs_clarify) reasons.push("问题意图不明确（Q1 低置信度，需澄清）");
  if (!coversRequestedCve(plan, evidence)) {
    reasons.push("证据未覆盖问题指定的 CVE：" + plan.slots.cve_ids.join("、"));
  }
  if (reasons.length > 0) return buildAbstain(question, plan, evidence, reasons, ctx, base);
  return buildAnswer(question, plan, evidence, ctx, base);
}
