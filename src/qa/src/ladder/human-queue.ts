/**
 * A-02 人工工单队列：接单与人工决策回流。
 *
 * 纪律：
 * - 人工决策是契约 decided_by=human 的唯一合法入口：必须过与阶梯同一套形状校验，
 *   并发布 decision.replies（可 bus.replay() 回放），不允许绕过的自由文本；
 * - 工单只存 typed questions 与轨迹 id，私有 state 一律不落库（A-03 隐私边界）；
 * - 重复决单 / 工单不存在 / 形状非法 → 显式抛错（fail-closed）；
 * - calibrated_prob 口径与阶梯人工层一致：choice 记 1、abstain 记 0、score 取原值
 *   （人工决策不做概率校准，不伪造中间置信度）。
 */
import { nowIso, sha256Json } from "@safetrace/shared";
import type { DecisionReply, EventBus, EventStore, HumanTicket } from "@safetrace/shared";
import { validateDecision } from "./decision-ladder.js";

const SCHEMA_VERSION = "1.1";

/** 人工工单队列存储（shared EventStore 的结构性子集；测试可用内存实现）。 */
export type HumanTicketQueueStore = Pick<EventStore, "getHumanTicket" | "claimHumanTicket">;

export interface ResolveHumanTicketOptions {
  store: HumanTicketQueueStore;
  bus?: EventBus;
  ticket_id: string;
  /** 人工标识（谁做的决策；落工单 resolved_by）。 */
  resolver_id: string;
  decision: DecisionReply["decision"];
  /** 决策理由（进 DecisionReply.fallback_reason 与 lineage；不含私有 state 内容）。 */
  rationale?: string;
}

export interface ResolveHumanTicketResult {
  reply: DecisionReply;
  ticket: HumanTicket;
}

/** 接单：pending → claimed。已 claim/resolve → false（不静默改状态）。 */
export async function claimHumanTicket(store: HumanTicketQueueStore, ticketId: string, claimant: string): Promise<HumanTicket> {
  const ticket = await store.getHumanTicket(ticketId);
  if (!ticket) throw new Error("人工工单不存在：" + ticketId);
  const applied = await store.claimHumanTicket(ticketId, claimant, nowIso());
  if (!applied) throw new Error("工单非 pending 态（status=" + ticket.status + "），不能接单：" + ticketId);
  const updated = await store.getHumanTicket(ticketId);
  return updated!;
}

/** 人工决单：校验 → 同库原子提交 reply 与 resolved → 本地投递 → lineage。 */
export async function resolveHumanTicket(opts: ResolveHumanTicketOptions): Promise<ResolveHumanTicketResult> {
  const ticket = await opts.store.getHumanTicket(opts.ticket_id);
  if (!ticket) throw new Error("人工工单不存在：" + opts.ticket_id);
  if (ticket.status === "resolved") throw new Error("工单已决，不能重复决单：" + opts.ticket_id);
  const invalid = validateDecision(ticket.questions, opts.decision);
  if (invalid) throw new Error("人工决策未通过契约校验：" + invalid);
  const decision = opts.decision;
  const reply: DecisionReply = {
    decision_id: ticket.decision_id,
    kind: ticket.kind,
    decision,
    calibrated_prob: typeof decision.score === "number"
      ? Math.max(0, Math.min(1, decision.score))
      : decision.choice ? 1 : 0,
    decided_by: "human",
    ...(opts.rationale ? { fallback_reason: opts.rationale } : {}),
    schema_version: SCHEMA_VERSION,
  };
  if (!opts.bus) throw new Error("人工决策必须落总线（decision.replies）才能回放；bus 未提供");
  opts.bus.assertTicketStore(opts.store);
  const resolvedAt = nowIso();
  const envelope = await opts.bus.resolveHumanTicket(ticket, opts.resolver_id, resolvedAt, reply);
  await opts.bus?.recordLineage({
    trace_id: ticket.trace_id,
    parent_lineage_ids: [],
    causation_id: envelope.event_id,
    stage: "human.ticket_resolve",
    operation_version: "human-ticket.v1",
    status: "success",
    started_at: resolvedAt,
    input_refs: [{ kind: "HumanTicket", id: ticket.ticket_id, sha256: sha256Json(ticket) }],
    output_refs: [
      { kind: "DecisionReply", id: reply.decision_id, sha256: sha256Json(reply) },
      { kind: "EventEnvelope", id: envelope.event_id, sha256: sha256Json(reply) },
    ],
    decision: { reason: opts.rationale ?? "human decision via ticket queue", review_required: false },
  });
  const updated = await opts.store.getHumanTicket(opts.ticket_id);
  return { reply, ticket: updated! };
}