/**
 * S2 情报总线 v0：模块间只通过契约与事件交互。
 * - 生产者 publish（信封入 EventStore，幂等）
 * - 消费者 subscribe（失败重试 3 次进死信，A1 可重放）
 * - Trace：publish 可传 trace_id/causation_id，贯穿 采集→富化→入库→问答
 */
import { makeEnvelope, type Envelope, type Topic } from "./envelope.js";
import { recordLineage as persistLineage } from "./lineage.js";
import type { DecisionReply } from "./types.js";
import type { HumanTicket, HumanTicketCommit, EventStore, LineageDraft, LineageRecord, ReviewCase, ReviewCaseDecision, ReviewCaseDraft, StoredPageSnapshot } from "./store.js";

export type Handler<T = unknown> = (payload: T, env: Envelope<T>) => Promise<void> | void;

export interface BusOptions {
  store: EventStore;
  maxRetries?: number;
  /** 死信/重试回调（A1 消费；默认仅入 store） */
  onDeadLetter?: (eventId: string, reason: string) => void;
}

export class EventBus {
  private handlers = new Map<Topic, Set<Handler>>();
  private deliveryFailures = new Map<string, number>();

  constructor(private opts: BusOptions) {}

  subscribe<T>(topic: Topic, handler: Handler<T>): () => void {
    let set = this.handlers.get(topic);
    if (!set) {
      set = new Set();
      this.handlers.set(topic, set);
    }
    set.add(handler as Handler);
    return () => set!.delete(handler as Handler);
  }

  /** 发布事件：入 store（幂等）+ 内存同步投递（重试/死信）。 */
  async publish<T>(
    topic: Topic,
    payload: T,
    meta: { trace_id?: string; causation_id?: string | null } = {},
  ): Promise<Envelope<T>> {
    const env = makeEnvelope(topic, payload, meta);
    const accepted = await this.opts.store.append(env);
    if (!accepted) return env; // 重复事件不重复投递
    await this.deliver(env);
    return env;
  }

  /** Queue commits must use this exact store; never split event and ticket databases. */
  assertTicketStore(store: unknown): void {
    if (store !== this.opts.store) throw new Error("human ticket store must be the bus event store");
  }

  async enqueueHumanTicket(ticket: HumanTicket, reply: DecisionReply): Promise<HumanTicketCommit> {
    const env = makeEnvelope("decision.replies", reply, { trace_id: ticket.trace_id });
    const committed = await this.opts.store.enqueueHumanTicketWithReply(ticket, env);
    if (committed.inserted) await this.deliver(committed.envelope);
    return committed;
  }

  async resolveHumanTicket(ticket: HumanTicket, resolver: string, resolvedAt: string, reply: DecisionReply): Promise<Envelope<DecisionReply>> {
    const env = makeEnvelope("decision.replies", reply, { trace_id: ticket.trace_id });
    if (!await this.opts.store.resolveHumanTicketWithReply(ticket.ticket_id, resolver, resolvedAt, env)) throw new Error("工单状态已变化，决单未生效（并发竞争）：" + ticket.ticket_id);
    // Crash here cannot lose the reply: it is already durable and can be replayed.
    await this.deliver(env);
    return env;
  }

  /** Read durable receipts without replaying subscriber side effects. */
  async readEvents<T>(topic: Topic, offset = 0, limit = 500): Promise<Envelope<T>[]> {
    return this.opts.store.read<T>(topic, offset, limit);
  }

  /** Append-only processing record; does not alter frozen public event topics/schemas. */
  async recordLineage(draft: LineageDraft): Promise<LineageRecord> {
    return persistLineage(this.opts.store, draft);
  }

  async readLineage(traceId: string, offset = 0, limit = 100): Promise<LineageRecord[]> {
    return this.opts.store.readLineage(traceId, offset, limit);
  }

  async getLastGoodPageSnapshot(sourceUrl: string): Promise<StoredPageSnapshot | undefined> {
    return this.opts.store.getLastGoodPageSnapshot(sourceUrl);
  }

  async saveLastGoodPageSnapshot(snapshot: StoredPageSnapshot): Promise<boolean> {
    return this.opts.store.saveLastGoodPageSnapshot(snapshot);
  }

  async getLastGoodPageSnapshotByHash(contentSha256: string): Promise<StoredPageSnapshot | undefined> {
    return this.opts.store.getLastGoodPageSnapshotByHash(contentSha256);
  }

  async enqueueReviewCase(review: ReviewCaseDraft): Promise<boolean> {
    return this.opts.store.enqueueReviewCase(review);
  }

  async getReviewCase(reviewId: string): Promise<ReviewCase | undefined> {
    return this.opts.store.getReviewCase(reviewId);
  }

  async listPendingReviewCases(offset = 0, limit = 100): Promise<ReviewCase[]> {
    return this.opts.store.listPendingReviewCases(offset, limit);
  }

  async appendReviewCaseDecision(decision: ReviewCaseDecision): Promise<boolean> {
    return this.opts.store.appendReviewCaseDecision(decision);
  }

  /** 投递一次；返回是否全部处理器成功（A-06 死信重投据此销档）。 */
  private async deliver<T>(env: Envelope<T>): Promise<boolean> {
    const set = this.handlers.get(env.topic);
    if (!set || set.size === 0) return true;
    let ok = true;
    for (const handler of set) {
      try {
        await handler(env.payload, env);
        this.deliveryFailures.delete(env.event_id);
      } catch (err) {
        ok = false;
        const n = (this.deliveryFailures.get(env.event_id) ?? 0) + 1;
        this.deliveryFailures.set(env.event_id, n);
        const max = this.opts.maxRetries ?? 3;
        if (n >= max) {
          const reason = err instanceof Error ? err.message : String(err);
          await this.opts.store.markDeadLetter(env.event_id, reason);
          this.opts.onDeadLetter?.(env.event_id, reason);
        }
        // L1 层语义：投递失败不阻断生产者（重试与死信由总线负责登记）
      }
    }
    return ok;
  }

  /**
   * 重投单条已入库事件（A-06 自愈：死信修复后的恢复手段）。
   * 与 replay 的区别：不重新 append（事件已持久、生产者副作用不重放），只对订阅者再投递一次；
   * 全部处理器成功 → 清除死信标记；仍然失败 → 保留死信并累计失败次数（可再次退避重投）。
   */
  async redeliver<T>(env: Envelope<T>): Promise<boolean> {
    // publish 可以仅持久化而无订阅者；死信重投则必须有实际消费者，
    // 不能把空投递视为恢复成功并销档（独立守护进程/退订后尤其如此）。
    const consumers = this.handlers.get(env.topic);
    if (!consumers || consumers.size === 0) return false;
    const ok = await this.deliver(env);
    if (ok) await this.opts.store.clearDeadLetter(env.event_id);
    return ok;
  }

  /** 重放：从 store 按主题重读并重新投递（死信修复后的恢复手段）。 */
  async replay<T>(topic: Topic, offset = 0, limit = 100): Promise<number> {
    const envs = await this.opts.store.read<T>(topic, offset, limit);
    for (const env of envs) await this.deliver(env);
    return envs.length;
  }
}
