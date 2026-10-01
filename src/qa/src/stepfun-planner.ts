import { degrade, screenPromptInjection, sha256, sha256Json } from "@safetrace/shared";
import type { EventBus, RetrievalResponse } from "@safetrace/shared";
import type { IntentKind, QueryPlan } from "./q1-intent.js";
import { strategyForIntent } from "./q1-intent.js";
import type { StepFunChatClient } from "./stepfun-answerer.js";

const INTENTS = new Set<IntentKind>(["impact_range", "remediation", "attack_chain", "trend", "concept", "paper_related"]);
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const SAFE_EFFORT_MIN_CONFIDENCE = 0.55;
const STEPPLAN_CONFIDENCE_THRESHOLD = 0.65;
const RETRIEVAL_SCORE_FLOOR = 0.3;

export interface StepFunPlannerOptions {
  provider: string;
  modelId: string;
  apiKeyConfigured: boolean;
  client?: StepFunChatClient;
  bus?: EventBus;
  traceId: string;
  parent_lineage_ids?: string[];
}

export interface Q1StepFunResult {
  plan: QueryPlan;
  attempted: boolean;
  used_llm: boolean;
  model_id?: string;
  fallback_reason?: string;
}

export interface Q2StepFunResult {
  retrieval: RetrievalResponse;
  attempted: boolean;
  used_llm: boolean;
  model_id?: string;
  fallback_reason?: string;
}

function safeClarifier(value: unknown, question: string): string | null {
  if (typeof value !== "string") return null;
  const raw = value.trim().replace(/^['"“「]|['"”」]$/g, "");
  if (raw.length < 8 || raw.length > 160 || /https?:\/\//i.test(raw) || /[\r\n]/.test(raw)) return null;
  const text = /[?？]$/.test(raw) ? raw : raw + "？";
  if (text.length > 160) return null;
  const allowedCves = new Set((question.match(CVE_RE) ?? []).map((id) => id.toUpperCase()));
  if ((text.match(CVE_RE) ?? []).some((id) => !allowedCves.has(id.toUpperCase()))) return null;
  return text;
}

function cloudQuerySafetyReason(texts: string[]): string | null {
  if (texts.some((text) => /(?:https?|file):\/\//i.test(text))) return "问题/查询包含 URL，未发送到 StepPlan";
  const screen = screenPromptInjection(texts);
  if (!screen.screened) return "A-04 注入筛查未完成，未发送到 StepPlan";
  if (!screen.allowed) return "A-04 注入筛查命中 " + screen.flags.join(",") + "，保留规则/检索";
  return null;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed.slice(start, end + 1));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}

function knownCveIds(text: string): string[] {
  return (text.match(CVE_RE) ?? []).map((id) => id.toUpperCase());
}

function scoreTop(evidence: RetrievalResponse): number {
  return evidence.chunks.reduce((best, chunk) => {
    const score = chunk.score_rerank ?? Math.max(chunk.score_dense ?? 0, chunk.score_sparse ?? 0);
    return Number.isFinite(score) ? Math.max(best, score) : best;
  }, 0);
}

function betterRetrieval(candidate: RetrievalResponse, original: RetrievalResponse): boolean {
  if (candidate.chunks.length === 0) return false;
  if (original.chunks.length === 0) return true;
  const candidateScore = scoreTop(candidate);
  const originalScore = scoreTop(original);
  return candidateScore > originalScore + 0.01 || (candidate.chunks.length > original.chunks.length && candidateScore >= originalScore);
}

function safePlannerFailure(layer: "q1" | "q2", error: unknown): string {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (message.includes("did not return the configured stepplan")) return "MG1 未返回 StepPlan provider，保留原规则/检索";
  if (message.includes("q1 json failed")) return "StepPlan Q1 输出不是通过校验的 JSON";
  if (message.includes("did not meet q1")) return "StepPlan 对 Q1 低置信弃权且未给有效澄清问题";
  if (message.includes("q2 json failed")) return "StepPlan Q2 输出不是通过校验的 JSON";
  if (message.includes("q2 query failed")) return "StepPlan Q2 改写未通过 CVE/URL/长度约束";
  if (/401|403/.test(message)) return "StepPlan 鉴权失败，保留原规则/检索";
  if (/429/.test(message)) return "StepPlan 触发频率限制，保留原规则/检索";
  const status = message.match(/http\s+(5\d\d)/i)?.[1];
  if (status) return "StepPlan 上游 HTTP " + status + "，保留原规则/检索";
  if (/timeout|timed out|abort/.test(message)) return "StepPlan 请求超时，保留原规则/检索";
  if (/scope|private data|data domain/.test(message)) return "出云安全闸门阻止 StepPlan 请求，保留原规则/检索";
  return (layer === "q1" ? "StepPlan Q1" : "StepPlan Q2") + " 网络/执行异常，保留原规则/检索";
}

async function modelLineageParents(bus: EventBus | undefined, traceId: string, before: Set<string>): Promise<string[]> {
  if (!bus) return [];
  const rows = await bus.readLineage(traceId, 0, 1000);
  return rows.filter((row) => row.stage === "mg1.chat" && !before.has(row.lineage_id)).map((row) => row.lineage_id);
}

async function emitRuleFallback(
  options: StepFunPlannerOptions,
  layer: "q1" | "q2",
  reason: string,
  inputRefs: Array<{ kind: string; id: string; sha256: string }>,
  extraParents: string[] = [],
): Promise<void> {
  let causationId: string | null = null;
  await degrade({
    layer: "L3",
    trigger: layer.toUpperCase() + " StepPlan helper unavailable; original rule/retrieval path retained: " + reason,
    degradedOf: layer + ":rule_fallback",
    traceId: options.traceId,
    label: layer === "q1" ? "StepPlan Q1 输出未通过校验，已保留规则分类/澄清" : "StepPlan Q2 改写未通过校验或未改善检索，已保留原检索结果",
    recoveryHint: "检查 STEP_PLAN_API_KEY、网络和 StepPlan 返回格式；原规则/检索结果仍可用。",
    emit: async (event) => {
      if (!options.bus) return;
      const envelope = await options.bus.publish("fallback.events", event, { trace_id: options.traceId });
      causationId = envelope.event_id;
    },
  });
  await options.bus?.recordLineage({
    trace_id: options.traceId,
    parent_lineage_ids: [...new Set([...(options.parent_lineage_ids ?? []), ...extraParents])],
    causation_id: causationId,
    stage: layer === "q1" ? "qa.q1_stepfun" : "qa.q2_stepfun_rewrite",
    operation_version: "stepfun." + layer + ".v1",
    status: "degraded",
    input_refs: inputRefs,
    output_refs: [],
    execution: { provider: "stepplan", model_id: options.modelId, model_version: "unversioned-api" },
    decision: { reason, fallback_to: layer === "q1" ? "q1_rules" : "original_retrieval" },
    error: "StepPlan output unavailable or rejected; deterministic result retained",
  });
}

export async function refineQ1WithStepFun(
  question: string,
  plan: QueryPlan,
  options: StepFunPlannerOptions,
): Promise<Q1StepFunResult> {
  const trimmed = question.trim();
  if ((!plan.needs_clarify && plan.confidence >= SAFE_EFFORT_MIN_CONFIDENCE) || trimmed.length < 8) {
    return { plan, attempted: false, used_llm: false };
  }
  if (options.provider !== "stepplan") return { plan, attempted: false, used_llm: false };
  const inputRefs = [
    { kind: "Query", id: options.traceId, sha256: sha256(question) },
    { kind: "QueryPlan", id: options.traceId, sha256: sha256Json(plan) },
  ];
  const screenReason = cloudQuerySafetyReason([trimmed, plan.rewrite_text, JSON.stringify(plan.slots)]);
  if (screenReason) {
    await emitRuleFallback(options, "q1", screenReason, inputRefs);
    return { plan, attempted: true, used_llm: false, fallback_reason: screenReason };
  }
  if (!options.apiKeyConfigured || !options.client) {
    const reason = "STEP_PLAN_API_KEY 或 planner client 未配置";
    await emitRuleFallback(options, "q1", reason, inputRefs);
    return { plan, attempted: true, used_llm: false, fallback_reason: reason };
  }

  const priorIds = new Set(options.bus ? (await options.bus.readLineage(options.traceId, 0, 1000)).map((row) => row.lineage_id) : []);
  try {
    const reply = await options.client.chat("planner", [
      { role: "system", content: "你只负责 Q1 意图分类，不回答漏洞事实。只能选择 intent=impact_range/remediation/attack_chain/trend/concept/paper_related；若 rule_intents 非空，只能从候选中选。无法判断时用 uncertain 并给一个简短澄清问题。不要补造 CVE、产品或版本，槽位由规则提供。只输出 JSON，例如 {\"intent\":\"uncertain\",\"clarify_question\":\"你想了解哪方面？\"}。" },
      { role: "user", content: JSON.stringify({ question: trimmed, rule_intents: plan.intents, rule_confidence: plan.confidence, extracted_slots: plan.slots }) },
    ], { temperature: 0, max_tokens: 512 }, options.traceId, "public", "qa.q1.intent");
    if (reply.provider !== "stepplan" || reply.model_id !== options.modelId || reply.degraded_to) {
      throw new Error("MG1 did not return the configured StepPlan planner");
    }
    const body = parseJsonObject(reply.text);
    const allowed = body && Object.keys(body).every((key) => ["intent", "confidence", "clarify_question"].includes(key));
    const intent = body?.intent;
    const confidence = body?.confidence;
    const confidenceMissing = confidence === undefined || confidence === null;
    const validConfidence = confidenceMissing || (typeof confidence === "number" && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1);
    const modelConfidence = typeof confidence === "number" ? confidence : undefined;
    const clarify = safeClarifier(body?.clarify_question, question);
    if (!allowed || typeof intent !== "string" || !(INTENTS.has(intent as IntentKind) || intent === "uncertain") || !validConfidence) {
      throw new Error("StepPlan Q1 JSON failed schema validation");
    }
    let resultPlan: QueryPlan;
    let reason: string;
    const agreesWithRule = plan.intents.length === 0 || (INTENTS.has(intent as IntentKind) && plan.intents.includes(intent as IntentKind));
    if (intent !== "uncertain" && (modelConfidence === undefined || modelConfidence >= STEPPLAN_CONFIDENCE_THRESHOLD) && agreesWithRule) {
      const { clarify_question: _unused, ...withoutClarifier } = plan;
      resultPlan = {
        ...withoutClarifier,
        intents: [intent as IntentKind],
        strategy: strategyForIntent(intent as IntentKind),
        needs_clarify: false,
        confidence: modelConfidence ?? plan.confidence,
        classifier_source: "stepplan",
      };
      reason = "StepPlan chose a valid Q1 intent; deterministic slots were preserved";
    } else if (clarify) {
      resultPlan = { ...plan, needs_clarify: true, clarify_question: clarify, classifier_source: "stepplan" };
      reason = "StepPlan abstained on intent and supplied a validated clarifier";
    } else {
      throw new Error("StepPlan did not meet Q1 confidence/clarifier rules");
    }
    const parents = [...new Set([...(options.parent_lineage_ids ?? []), ...await modelLineageParents(options.bus, options.traceId, priorIds)])];
    await options.bus?.recordLineage({
      trace_id: options.traceId, parent_lineage_ids: parents, causation_id: null,
      stage: "qa.q1_stepfun", operation_version: "stepfun.q1.v1", status: "success",
      input_refs: inputRefs, output_refs: [{ kind: "QueryPlan", id: options.traceId, sha256: sha256Json(resultPlan) }],
      execution: { provider: reply.provider, model_id: reply.model_id, model_version: "unversioned-api" },
      decision: { reason },
    });
    return { plan: resultPlan, attempted: true, used_llm: true, model_id: reply.model_id };
  } catch (error) {
    const reason = safePlannerFailure("q1", error);
    const parents = await modelLineageParents(options.bus, options.traceId, priorIds);
    await emitRuleFallback(options, "q1", reason, inputRefs, parents);
    return { plan, attempted: true, used_llm: false, fallback_reason: reason };
  }
}

export function shouldRewriteQ2WithStepFun(plan: QueryPlan, evidence: RetrievalResponse): boolean {
  if (plan.needs_clarify) return false;
  const topScore = scoreTop(evidence);
  const needsMultipleSources = plan.strategy === "multi_hop" || plan.strategy === "timeline" || plan.strategy === "attack_chain";
  return evidence.chunks.length === 0 || topScore < RETRIEVAL_SCORE_FLOOR || (needsMultipleSources && evidence.chunks.length < 2);
}

export async function rewriteQ2WithStepFun(
  question: string,
  plan: QueryPlan,
  original: RetrievalResponse,
  options: StepFunPlannerOptions,
  search: (queryText: string, parentLineageIds: string[]) => Promise<RetrievalResponse>,
): Promise<Q2StepFunResult> {
  const topScore = scoreTop(original);
  if (!shouldRewriteQ2WithStepFun(plan, original)) return { retrieval: original, attempted: false, used_llm: false };
  if (options.provider !== "stepplan") return { retrieval: original, attempted: false, used_llm: false };
  const inputRefs = [
    { kind: "Query", id: options.traceId, sha256: sha256(question) },
    { kind: "QueryPlan", id: options.traceId, sha256: sha256Json(plan) },
    { kind: "RetrievalResponse", id: original.query_id, sha256: sha256Json(original) },
  ];
  const screenReason = cloudQuerySafetyReason([question.trim(), plan.rewrite_text, JSON.stringify({ intents: plan.intents, slots: plan.slots })]);
  if (screenReason) {
    await emitRuleFallback(options, "q2", screenReason, inputRefs);
    return { retrieval: original, attempted: true, used_llm: false, fallback_reason: screenReason };
  }
  if (!options.apiKeyConfigured || !options.client) {
    const reason = "STEP_PLAN_API_KEY 或 planner client 未配置";
    await emitRuleFallback(options, "q2", reason, inputRefs);
    return { retrieval: original, attempted: true, used_llm: false, fallback_reason: reason };
  }

  const priorIds = new Set(options.bus ? (await options.bus.readLineage(options.traceId, 0, 1000)).map((row) => row.lineage_id) : []);
  try {
    const reply = await options.client.chat("planner", [
      { role: "system", content: "你只负责改写 Q2 的检索词，不要回答问题或创造证据。保留用户已指定的 CVE ID；不能添加其他 CVE、URL、产品或版本；如果原问题已经清楚就只做最小改写。只输出 JSON：{\"query\":string}。" },
      { role: "user", content: JSON.stringify({ question: question.trim(), intents: plan.intents, slots: plan.slots, current_query: plan.rewrite_text, retrieval_hits: original.chunks.length, top_score: topScore }) },
    ], { temperature: 0, max_tokens: 512 }, options.traceId, "public", "qa.q2.rewrite");
    if (reply.provider !== "stepplan" || reply.model_id !== options.modelId || reply.degraded_to) {
      throw new Error("MG1 did not return the configured StepPlan planner");
    }
    const body = parseJsonObject(reply.text);
    if (!body || Object.keys(body).length !== 1 || typeof body.query !== "string") throw new Error("StepPlan Q2 JSON failed schema validation");
    const rewritten = body.query.trim();
    const askedCves = new Set(plan.slots.cve_ids.map((id) => id.toUpperCase()));
    const returnedCves = knownCveIds(rewritten);
    if (rewritten.length < 4 || rewritten.length > 400 || /[\r\n]/.test(rewritten) || /https?:\/\//i.test(rewritten) || returnedCves.some((id) => !askedCves.has(id)) || plan.slots.cve_ids.some((id) => !rewritten.toUpperCase().includes(id.toUpperCase()))) {
      throw new Error("StepPlan Q2 query failed validation");
    }
    if (rewritten === plan.rewrite_text.trim()) {
      const reason = "StepPlan 未改变 Q2 查询，保留原始检索";
      const parents = await modelLineageParents(options.bus, options.traceId, priorIds);
      await emitRuleFallback(options, "q2", reason, inputRefs, parents);
      return { retrieval: original, attempted: true, used_llm: false, fallback_reason: reason, model_id: reply.model_id };
    }
    const modelParents = await modelLineageParents(options.bus, options.traceId, priorIds);
    const searchParents = [...new Set([...(options.parent_lineage_ids ?? []), ...modelParents])];
    const candidate = await search(rewritten, searchParents);
    if (!betterRetrieval(candidate, original)) {
      const reason = "改写后检索没有提升，保留原始 Q2 结果";
      await emitRuleFallback(options, "q2", reason, inputRefs, modelParents);
      return { retrieval: original, attempted: true, used_llm: true, fallback_reason: reason, model_id: reply.model_id };
    }
    const finalParents = [...new Set([...searchParents, ...await modelLineageParents(options.bus, options.traceId, priorIds)])];
    await options.bus?.recordLineage({
      trace_id: options.traceId, parent_lineage_ids: finalParents, causation_id: null,
      stage: "qa.q2_stepfun_rewrite", operation_version: "stepfun.q2-rewrite.v1", status: "success",
      input_refs: inputRefs,
      output_refs: [{ kind: "QueryRewrite", id: options.traceId, sha256: sha256(rewritten) }, { kind: "RetrievalResponse", id: candidate.query_id, sha256: sha256Json(candidate) }],
      execution: { provider: reply.provider, model_id: reply.model_id, model_version: "unversioned-api" },
      decision: { reason: "Rewritten query improved retrieval; source evidence still comes only from Q2" },
    });
    return { retrieval: candidate, attempted: true, used_llm: true, model_id: reply.model_id };
  } catch (error) {
    const reason = safePlannerFailure("q2", error);
    const parents = await modelLineageParents(options.bus, options.traceId, priorIds);
    await emitRuleFallback(options, "q2", reason, inputRefs, parents);
    return { retrieval: original, attempted: true, used_llm: false, fallback_reason: reason };
  }
}
