import { screenPromptInjection, sha256Json } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest, EventBus } from "@safetrace/shared";
import type { StepFunChatClient } from "../stepfun-answerer.js";
import { runDecisionLadder } from "./decision-ladder.js";
import type { DecisionResolution, LadderContext, LadderOptions, LlmResolver, RuleResolver } from "./decision-ladder.js";

const OPTION_LABEL = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const PUBLIC_FACT_FIELDS = new Set([
  "cve_ids", "product", "products", "versions", "severity", "cvss_v3_base", "epss_score", "kev_flag",
  "exploit_maturity", "rule_candidate", "evidence_count", "source_count", "quality_score", "dq_verdict",
]);
const SAFE_ENUMS: Record<string, Set<string>> = {
  severity: new Set(["critical", "high", "medium", "low", "unknown", "info"]),
  exploit_maturity: new Set(["none", "poc", "weaponized", "actively_exploited", "unknown"]),
  dq_verdict: new Set(["pass", "degrade", "review", "quarantine"]),
};

export interface StepPlanDecisionOptions {
  provider: string;
  modelId: string;
  apiKeyConfigured: boolean;
  client?: StepFunChatClient;
  bus?: EventBus;
  min_model_confidence?: number;
}
export interface StepPlanDecisionHandlerOptions extends StepPlanDecisionOptions, Omit<LadderOptions, "llm" | "bus"> {
  bus?: EventBus;
}
export class DecisionRequestValidationError extends Error {
  readonly statusCode = 400;
  constructor() { super("DecisionRequest contract validation failed"); }
}

type PublicFacts = Record<string, string | number | boolean | string[]>;
interface Projection {
  kind: DecisionRequest["kind"];
  facts: PublicFacts;
  question: { q_id: string; type: "choice"; options: string[] };
  calibrated: Record<string, number>;
}

function objectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function safeString(value: unknown, max = 160): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max && !/[\r\n]/.test(value) && !/(?:https?|file):\/\//i.test(value);
}
function projectPublicFacts(raw: unknown): PublicFacts | null {
  if (!objectRecord(raw)) return null;
  const out: PublicFacts = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!PUBLIC_FACT_FIELDS.has(key)) continue;
    if (key === "cve_ids") {
      if (!Array.isArray(value) || value.length > 10 || value.some((item) => typeof item !== "string" || !CVE_ID.test(item))) return null;
      out[key] = value as string[];
      continue;
    }
    if (key === "products" || key === "versions") {
      if (!Array.isArray(value) || value.length > 20 || value.some((item) => !safeString(item, 120))) return null;
      out[key] = value as string[];
      continue;
    }
    if (key === "severity" || key === "exploit_maturity" || key === "dq_verdict") {
      if (!safeString(value, 64) || !SAFE_ENUMS[key]?.has(value.toLowerCase())) return null;
      out[key] = value.toLowerCase();
      continue;
    }
    if (key === "product" || key === "rule_candidate") {
      if (!safeString(value, 120) || (key === "rule_candidate" && !OPTION_LABEL.test(value))) return null;
      out[key] = value;
      continue;
    }
    if (key === "kev_flag") {
      if (typeof value !== "boolean") return null;
      out[key] = value;
      continue;
    }
    if (key === "cvss_v3_base") {
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 10) return null;
      out[key] = value;
      continue;
    }
    if (key === "epss_score" || key === "quality_score") {
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) return null;
      out[key] = value;
      continue;
    }
    if (key === "evidence_count" || key === "source_count") {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 1000) return null;
      out[key] = value;
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

function readCalibratedOptionMap(state: Record<string, unknown>, options: string[]): Record<string, number> | null {
  if (!objectRecord(state.calibrated_option_probabilities)) return null;
  if (typeof state.calibration_source !== "string" || !["tool", "rule", "policy"].includes(state.calibration_source)) return null;
  const raw = state.calibrated_option_probabilities;
  if (Object.keys(raw).length !== options.length || Object.keys(raw).some((key) => !options.includes(key))) return null;
  const calibrated: Record<string, number> = {};
  for (const option of options) {
    const probability = raw[option];
    if (typeof probability !== "number" || !Number.isFinite(probability) || probability < 0 || probability > 1) return null;
    calibrated[option] = probability;
  }
  const total = Object.values(calibrated).reduce((sum, probability) => sum + probability, 0);
  return total >= 0.99 && total <= 1.01 ? calibrated : null;
}

export function createCalibratedRuleResolver(): RuleResolver {
  return async (ctx) => {
    if (ctx.questions.length !== 1) return null;
    const question = ctx.questions[0]!;
    if (question.type !== "choice" || !Array.isArray(question.options) || question.options.length < 2 || question.options.length > 20) return null;
    if (question.options.some((option) => !OPTION_LABEL.test(option)) || new Set(question.options).size !== question.options.length) return null;
    if (ctx.state.calibration_source !== "rule" || !objectRecord(ctx.state.public_facts)) return null;
    const candidate = ctx.state.public_facts.rule_candidate;
    if (typeof candidate !== "string" || !question.options.includes(candidate)) return null;
    const calibrated = readCalibratedOptionMap(ctx.state, question.options);
    const probability = calibrated?.[candidate];
    if (probability === undefined || probability < 0.65) return null;
    return { choice: candidate, score: probability };
  };
}
function buildProjection(ctx: LadderContext): Projection | null {
  const state = ctx.state;
  if (state.data_domain !== "public" || state.stepfun_opt_in !== true || state.injection_screened !== true) return null;
  if (ctx.questions.length !== 1) return null;
  const typed = ctx.questions[0]!;
  if (typed.type !== "choice" || !Array.isArray(typed.options) || typed.options.length < 2 || typed.options.length > 20) return null;
  const options = typed.options;
  if (options.some((option) => !OPTION_LABEL.test(option)) || new Set(options).size !== options.length) return null;
  if (!safeString(typed.q_id, 64) || !/^[A-Za-z0-9_-]+$/.test(typed.q_id)) return null;
  const facts = projectPublicFacts(state.public_facts);
  if (!facts) return null;
  const calibrated = readCalibratedOptionMap(state, options);
  if (!calibrated) return null;
  return { kind: ctx.kind, facts, question: { q_id: typed.q_id, type: "choice", options }, calibrated };
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = text.trim().replace(/^\x60\x60\x60(?:json)?\s*/i, "").replace(/\s*\x60\x60\x60$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const value: unknown = JSON.parse(trimmed.slice(start, end + 1));
    return objectRecord(value) ? value : null;
  } catch { return null; }
}

async function writeDecisionLineage(bus: EventBus | undefined, ctx: LadderContext, status: "success" | "review" | "failed", input: unknown, output: unknown, provider: string, modelId: string, reason: string, parents: string[] = []): Promise<void> {
  await bus?.recordLineage({
    trace_id: ctx.trace_id,
    parent_lineage_ids: parents,
    stage: "decide.stepfun",
    operation_version: "stepfun.decision.v1",
    status,
    input_refs: [{ kind: "PublicDecisionProjection", id: ctx.decision_id, sha256: sha256Json(input) }],
    output_refs: [{ kind: "DecisionCandidate", id: ctx.decision_id, sha256: sha256Json(output) }],
    execution: { provider, model_id: modelId, model_version: "unversioned-api" },
    decision: { reason },
  });
}

export function createStepPlanDecisionResolver(options: StepPlanDecisionOptions): LlmResolver | undefined {
  if (options.provider !== "stepplan" || !options.apiKeyConfigured || !options.client) return undefined;
  const client = options.client;
  return async (ctx): Promise<DecisionResolution | null> => {
    const projection = buildProjection(ctx);
    if (!projection || !Object.values(projection.calibrated).some((probability) => probability >= 0.65)) return null;
    const modelInput = { kind: projection.kind, public_facts: projection.facts, question: { type: "choice" as const, options: projection.question.options } };
    const screen = screenPromptInjection([JSON.stringify(modelInput)]);
    if (!screen.screened || !screen.allowed) return null;
    const before = new Set(options.bus ? (await options.bus.readLineage(ctx.trace_id, 0, 1000)).map((row) => row.lineage_id) : []);
    try {
      const reply = await client.chat("planner", [
        { role: "system", content: "你是决策候选选择器。只使用给定的公开结构化事实和 options，choice 必须逐字等于其中一个 option；不确定时 abstain=true。confidence 是仅用于拒答阈值的模型自评，不是 calibrated_prob。只输出 JSON：{\"choice\":\"option\",\"confidence\":0.9,\"abstain\":false}。" },
        { role: "user", content: JSON.stringify(modelInput) },
      ], { temperature: 0, max_tokens: 256 }, ctx.trace_id, "public");
      if (reply.provider !== "stepplan" || reply.model_id !== options.modelId || reply.degraded_to) throw new Error("StepPlan decision provider/model mismatch or fallback");
      const body = parseJsonObject(reply.text);
      if (!body || Object.keys(body).some((key) => !["choice", "confidence", "abstain"].includes(key)) || typeof body.abstain !== "boolean") throw new Error("StepPlan decision JSON schema rejected");
      if ((body.abstain === true && Object.keys(body).length !== 1) || (body.abstain === false && Object.keys(body).length !== 3)) throw new Error("StepPlan decision JSON fields do not match abstain state");
      const parents = options.bus ? (await options.bus.readLineage(ctx.trace_id, 0, 1000)).filter((row) => row.stage === "mg1.chat" && !before.has(row.lineage_id)).map((row) => row.lineage_id) : [];
      if (body.abstain === true) {
        await writeDecisionLineage(options.bus, ctx, "review", modelInput, { abstain: true }, reply.provider, reply.model_id, "StepPlan abstained; option list and state were not changed", parents);
        return null;
      }
      if (typeof body.choice !== "string" || !projection.question.options.includes(body.choice) || typeof body.confidence !== "number" || !Number.isFinite(body.confidence) || body.confidence < 0 || body.confidence > 1) {
        throw new Error("StepPlan choice/confidence failed typed-output validation");
      }
      if (body.confidence < (options.min_model_confidence ?? 0.75)) {
        await writeDecisionLineage(options.bus, ctx, "review", modelInput, { abstain: true }, reply.provider, reply.model_id, "StepPlan model confidence below review threshold", parents);
        return null;
      }
      const calibrated = projection.calibrated[body.choice];
      if (calibrated === undefined || calibrated < 0.65) {
        await writeDecisionLineage(options.bus, ctx, "review", modelInput, { rejected: true }, reply.provider, reply.model_id, "Trusted upstream calibrated probability is below the decision threshold", parents);
        return null;
      }
      const decision = { choice: body.choice };
      await options.bus?.recordLineage({
        trace_id: ctx.trace_id,
        parent_lineage_ids: parents,
        stage: "decide.stepfun",
        operation_version: "stepfun.decision.v1",
        status: "success",
        input_refs: [{ kind: "PublicDecisionProjection", id: ctx.decision_id, sha256: sha256Json(modelInput) }],
        output_refs: [{ kind: "DecisionCandidate", id: ctx.decision_id, sha256: sha256Json({ decision, calibrated_prob: calibrated }) }],
        execution: { provider: reply.provider, model_id: reply.model_id, model_version: "unversioned-api" },
        decision: { reason: "StepPlan selected an allowed option; calibrated_prob came from trusted upstream option probabilities, not model self-rating" },
      });
      return { decision, calibrated_prob: calibrated };
    } catch {
      await writeDecisionLineage(options.bus, ctx, "failed", modelInput, { failed: true }, options.provider, options.modelId, "StepPlan decision request or validation failed; response text not retained");
      throw new Error("StepPlan decision request or validation failed");
    }
  };
}

function parseDecisionRequest(raw: unknown): DecisionRequest {
  if (!objectRecord(raw)) throw new DecisionRequestValidationError();
  const allowedRoot = new Set(["decision_id", "kind", "state", "questions", "trace_id", "schema_version"]);
  if (Object.keys(raw).some((key) => !allowedRoot.has(key))) throw new DecisionRequestValidationError();
  if (typeof raw.decision_id !== "string" || raw.decision_id.length < 1) throw new DecisionRequestValidationError();
  if (typeof raw.kind !== "string" || !["y5_triage", "q1_route", "q3_sufficiency", "dq_verdict"].includes(raw.kind)) throw new DecisionRequestValidationError();
  if (!objectRecord(raw.state) || !Array.isArray(raw.questions) || raw.questions.length < 1) throw new DecisionRequestValidationError();
  if (typeof raw.trace_id !== "string" || typeof raw.schema_version !== "string" || !/^\d+\.\d+$/.test(raw.schema_version)) throw new DecisionRequestValidationError();
  const allowedQuestion = new Set(["q_id", "type", "options", "rubric", "cardinality_max"]);
  for (const question of raw.questions) {
    if (!objectRecord(question) || Object.keys(question).some((key) => !allowedQuestion.has(key)) || typeof question.q_id !== "string" || !["choice", "score", "noul"].includes(String(question.type))) throw new DecisionRequestValidationError();
    if (question.options !== undefined && (!Array.isArray(question.options) || question.options.some((option) => typeof option !== "string"))) throw new DecisionRequestValidationError();
    if (question.rubric !== undefined && typeof question.rubric !== "string") throw new DecisionRequestValidationError();
    if (question.cardinality_max !== undefined && (typeof question.cardinality_max !== "number" || !Number.isInteger(question.cardinality_max) || question.cardinality_max > 255)) throw new DecisionRequestValidationError();
  }
  return raw as unknown as DecisionRequest;
}

export function createStepPlanDecisionHandler(options: StepPlanDecisionHandlerOptions): (raw: unknown) => Promise<DecisionReply> {
  const llm = createStepPlanDecisionResolver(options);
  return async (raw) => {
    const request = parseDecisionRequest(raw);
    const ladder: LadderOptions = { bus: options.bus, tool: options.tool, rule: options.rule ?? createCalibratedRuleResolver(), human: options.human, onFallback: options.onFallback, ...(llm ? { llm } : {}) };
    return (await runDecisionLadder(request, ladder)).reply;
  };
}
