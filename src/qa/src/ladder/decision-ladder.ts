/**
 * A-02 四层兜底阶梯：工具 → 规则 → LLM → 人工。
 * 纪律（禁砍项）：
 * - 逐层尝试，任一层成功即返回，decided_by 如实记录该层；
 * - 任一层失败/不可用/低置信度弃权 → 显式下坠，不得静默跳过；
 * - LLM 层必须允许"弃权"（低置信度返回空）才能下坠到人工层；
 * - 全量 decision.replies 入总线，可 bus.replay() 重放；
 * - escalation_trace 记录完整阶梯路径（含每层耗时与失败原因）。
 */
import { degrade, nowIso, sha256Json } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest, EventBus, FallbackEvent, HumanTicket, TypedQuestion } from "@safetrace/shared";

/** 阶梯层名。tool 层的 decided_by 记 rule_fallback（契约无 tool 通道）。 */
export type LadderLayer = "tool" | "rule" | "llm" | "human";

export interface LadderContext {
  decision_id: string;
  kind: DecisionRequest["kind"];
  state: Record<string, unknown>;
  questions: DecisionRequest["questions"];
  trace_id: string;
}

export interface LadderAttempt {
  layer: LadderLayer;
  status: "success" | "abstained" | "unavailable" | "failed";
  reason: string;
  latency_ms: number;
}

export interface LadderResult {
  reply: DecisionReply;
  escalation_trace: LadderAttempt[];
  /** 阶梯是否发生过下坠（冒烟/审计断言用）。 */
  escalated: boolean;
  /** A-02：全链未决时入队的人工工单 id；已决时为 undefined。 */
  ticket_id?: string;
}

/** A-02：人工工单存储（shared EventStore 的结构性子集；测试可用内存实现）。 */
export interface HumanTicketStore {
  enqueueHumanTicket(ticket: HumanTicket): Promise<boolean>;
}

/** 工具层：调用方已备好的确定性结果。 */
export type ToolResolver = (ctx: LadderContext) => Promise<DecisionReply["decision"] | null>;
/** 规则层：确定性规则决策（models.yml decision role = rule-fallback-v0）。 */
export type RuleResolver = (ctx: LadderContext) => Promise<DecisionReply["decision"] | null>;
/** 可显式携带由可信上游校准的概率；模型自评不直接冒充 calibrated_prob。 */
export interface DecisionResolution { decision: DecisionReply["decision"]; calibrated_prob: number }
/** LLM 层：返回 null 表示低置信度弃权（允许下坠到人工层）。 */
export type LlmResolver = (ctx: LadderContext) => Promise<DecisionReply["decision"] | DecisionResolution | null>;
/** 人工层：未接入人工队列时返回 null（明确挂起，不伪造决策）。 */
export type HumanResolver = (ctx: LadderContext) => Promise<DecisionReply["decision"] | null>;

export interface LadderOptions {
  tool?: ToolResolver;
  rule?: RuleResolver;
  llm?: LlmResolver;
  human?: HumanResolver;
  bus?: EventBus;
  onFallback?: (event: FallbackEvent) => void | Promise<void>;
  /** A-02：全链未决时入队人工工单；缺省只挂起不派单（显式告知无队列）。 */
  ticketStore?: HumanTicketStore;
}

const SCHEMA_VERSION = "1.1";

/** 阶梯层 → 契约 DecidedBy 的如实映射。 */
export function decidedByFor(layer: LadderLayer): DecisionReply["decided_by"] {
  if (layer === "llm") return "llm_fallback";
  if (layer === "human") return "human";
  return "rule_fallback";
}

/**
 * 决策形状校验（人工工单侧复用同一口径：人工决策也要过契约校验，不许绕过的自由文本）。
 * 返回 undefined = 合法；否则为可读的非法原因。
 */
export function validateDecision(questions: TypedQuestion[], decision: DecisionReply["decision"]): string | undefined {
  const record = decision as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["choice", "score", "abstain"].includes(key))) return "decision contains unsupported fields";
  if (record.abstain === true) {
    return record.choice === undefined && record.score === undefined ? undefined : "abstain cannot include choice or score";
  }
  if (questions.length !== 1) return "single-decision reply requires exactly one typed question";
  const question = questions[0]!;
  if (record.abstain !== undefined && record.abstain !== false) return "abstain must be boolean";
  if (question.type === "choice") {
    if (typeof record.choice !== "string" || !question.options?.includes(record.choice)) return "choice must exactly match a typed option";
    if (record.score !== undefined && (typeof record.score !== "number" || !Number.isFinite(record.score) || record.score < 0 || record.score > 1)) return "confidence score must be within 0..1";
    return undefined;
  }
  if (question.type === "score") {
    if (record.choice !== undefined || typeof record.score !== "number" || !Number.isFinite(record.score) || record.score < 0 || record.score > 1) return "score question requires a numeric score within 0..1";
    return undefined;
  }
  return "noul question requires explicit abstention until free-text decision semantics are defined";
}

function isDecisionResolution(value: unknown): value is DecisionResolution {
  return typeof value === "object" && value !== null && !Array.isArray(value) && "decision" in value;
}

/** 执行四层阶梯。任一层不可用时登记 FallbackEvent 并显式下坠（禁静默）。 */
export async function runDecisionLadder(req: DecisionRequest, opts: LadderOptions = {}): Promise<LadderResult> {
  const ctx: LadderContext = {
    decision_id: req.decision_id,
    kind: req.kind,
    state: req.state,
    questions: req.questions,
    trace_id: req.trace_id,
  };
  const trace: LadderAttempt[] = [];
  const startedAt = nowIso();

  const publishReply = async (reply: DecisionReply): Promise<string | null> => {
    const envelope = await opts.bus?.publish("decision.replies", reply, { trace_id: req.trace_id });
    return envelope?.event_id ?? null;
  };

  const finish = async (layer: LadderLayer, resolved: DecisionResolution): Promise<LadderResult> => {
    const failures = trace.filter((a) => a.status !== "success");
    const decision = resolved.decision;
    const reply: DecisionReply = {
      decision_id: req.decision_id,
      kind: req.kind,
      decision,
      calibrated_prob: resolved.calibrated_prob ?? (typeof decision.score === "number" ? Math.max(0, Math.min(1, decision.score)) : (decision.choice ? 1 : 0)),
      // 契约 DecidedBy 无 tool 通道：工具层与规则层都如实记 rule_fallback；
      // llm 层记 llm_fallback；人工层在 v1.1 契约中已有 human 通道，不得冒充规则层。
      decided_by: decidedByFor(layer),
      ...(failures.length > 0 ? { fallback_reason: failures.map((a) => a.layer + ":" + a.reason).join("; ") } : {}),
      schema_version: SCHEMA_VERSION,
    };
    const eventId = await publishReply(reply);
    await opts.bus?.recordLineage({
      trace_id: req.trace_id,
      parent_lineage_ids: [],
      causation_id: eventId,
      stage: "decide.ladder",
      operation_version: "ladder." + layer + ".v1",
      status: failures.length > 0 ? "degraded" : "success",
      started_at: startedAt,
      input_refs: [{ kind: "DecisionRequest", id: req.decision_id, sha256: sha256Json(req) }],
      output_refs: [{ kind: "DecisionReply", id: reply.decision_id, sha256: sha256Json(reply) }],
      decision: { reason: "decided_by=" + reply.decided_by },
    });
    return { reply, escalation_trace: trace, escalated: failures.length > 0 };
  };

  const attemptLayer = async (layer: LadderLayer, resolver: ToolResolver | RuleResolver | LlmResolver | HumanResolver | undefined): Promise<DecisionResolution | null> => {
    const t0 = Date.now();
    if (!resolver) {
      trace.push({ layer, status: "unavailable", reason: layer + " 层未接入", latency_ms: Date.now() - t0 });
      await degradeFallback(layer, layer + " 层未接入", ctx, opts);
      return null;
    }
    try {
      const raw = await resolver(ctx);
      if (raw === null) {
        trace.push({ layer, status: "abstained", reason: layer + " 层低置信度弃权", latency_ms: Date.now() - t0 });
        await degradeFallback(layer, layer + " 层低置信度弃权（显式下坠）", ctx, opts);
        return null;
      }
      const resolution: DecisionResolution = isDecisionResolution(raw)
        ? raw
        : { decision: raw as DecisionReply["decision"], calibrated_prob: typeof raw.score === "number" ? raw.score : (raw.choice ? 1 : 0) };
      if (!Number.isFinite(resolution.calibrated_prob) || resolution.calibrated_prob < 0 || resolution.calibrated_prob > 1) throw new Error("calibrated_prob must be within 0..1");
      const invalid = validateDecision(req.questions, resolution.decision);
      if (invalid) throw new Error("结构化决策输出未通过验证：" + invalid);
      if (resolution.decision.abstain === true) {
        trace.push({ layer, status: "abstained", reason: layer + " 层显式 abstain", latency_ms: Date.now() - t0 });
        await degradeFallback(layer, layer + " 层显式 abstain（显式下坠）", ctx, opts);
        return null;
      }
      trace.push({ layer, status: "success", reason: "validated decision", latency_ms: Date.now() - t0 });
      return resolution;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      trace.push({ layer, status: "failed", reason: layer + " 层执行失败", latency_ms: Date.now() - t0 });
      await degradeFallback(layer, layer + " 层执行失败：" + msg, ctx, opts);
      return null;
    }
  };

  const unresolved = async (): Promise<LadderResult> => {
    const reply: DecisionReply = {
      decision_id: req.decision_id,
      kind: req.kind,
      decision: { abstain: true },
      calibrated_prob: 0,
      decided_by: "human",
      fallback_reason: "阶梯未决：等待人工复核",
      schema_version: SCHEMA_VERSION,
    };
    const eventId = await publishReply(reply);
    // A-02：全链未决 → 入队人工工单（幂等按 ticket_id）。缺省不派单时显式记录，不假装有人接。
    const ticketId = "ticket_" + req.decision_id;
    let queued: boolean | undefined;
    if (opts.ticketStore) {
      queued = await opts.ticketStore.enqueueHumanTicket({
        ticket_id: ticketId,
        decision_id: req.decision_id,
        trace_id: req.trace_id,
        kind: req.kind,
        questions: req.questions,
        status: "pending",
        reason: trace.map((a) => a.layer + ":" + a.status).join("; "),
        created_at: startedAt,
      });
    }
    await opts.bus?.recordLineage({
      trace_id: req.trace_id,
      parent_lineage_ids: [],
      causation_id: eventId,
      stage: "decide.ladder",
      operation_version: "ladder.human.v1",
      status: "review",
      started_at: startedAt,
      input_refs: [{ kind: "DecisionRequest", id: req.decision_id, sha256: sha256Json(req) }],
      output_refs: [
        { kind: "DecisionReply", id: reply.decision_id, sha256: sha256Json(reply) },
        ...(opts.ticketStore ? [{ kind: "HumanTicket", id: ticketId, sha256: sha256Json({ ticket_id: ticketId, decision_id: req.decision_id, kind: req.kind, status: "pending" }) }] : []),
      ],
      decision: {
        reason: opts.ticketStore
          ? "ladder unresolved; human ticket queued (" + (queued ? "new" : "idempotent replay") + ")"
          : "ladder unresolved; await human review (no ticket store attached)",
        review_required: true,
      },
    });
    return { reply, escalation_trace: trace, escalated: true, ...(opts.ticketStore ? { ticket_id: ticketId } : {}) };
  };

  const toolDecision = await attemptLayer("tool", opts.tool);
  if (toolDecision) return finish("tool", toolDecision);
  const ruleDecision = await attemptLayer("rule", opts.rule);
  if (ruleDecision) return finish("rule", ruleDecision);
  const llmDecision = await attemptLayer("llm", opts.llm);
  if (llmDecision) return finish("llm", llmDecision);
  const humanDecision = await attemptLayer("human", opts.human);
  if (humanDecision) return finish("human", humanDecision);
  return unresolved();
}

async function degradeFallback(layer: LadderLayer, trigger: string, ctx: LadderContext, opts: LadderOptions): Promise<void> {
  await degrade({
    layer: "L2",
    trigger: "决策阶梯 " + layer + " 层：" + trigger,
    degradedOf: "ladder:" + layer,
    traceId: ctx.trace_id,
    label: "决策层 " + layer + " 未决，已显式下坠至下一层",
    recoveryHint: "检查该层依赖或转人工",
    emit: async (e) => {
      await opts.bus?.publish("fallback.events", e, { trace_id: ctx.trace_id });
      await opts.onFallback?.(e);
    },
  });
}
