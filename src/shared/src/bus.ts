/**
 * S2 情报总线 v0：模块间只通过契约与事件交互。
 * - 生产者 publish（信封入 EventStore，幂等）
 * - 消费者 subscribe（失败重试 3 次进死信，A1 可重放）
 * - Trace：publish 可传 trace_id/causation_id，贯穿 采集→富化→入库→问答
 */
import { makeEnvelope, type Envelope, type Topic } from "./envelope.js";
import type { EventStore } from "./store.js";

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

  private async deliver<T>(env: Envelope<T>): Promise<void> {
    const set = this.handlers.get(env.topic);
    if (!set || set.size === 0) return;
    for (const handler of set) {
      try {
        await handler(env.payload, env);
        this.deliveryFailures.delete(env.event_id);
      } catch (err) {
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
  }

  /** 重放：从 store 按主题重读并重新投递（死信修复后的恢复手段）。 */
  async replay<T>(topic: Topic, offset = 0, limit = 100): Promise<number> {
    const envs = await this.opts.store.read<T>(topic, offset, limit);
    for (const env of envs) await this.deliver(env);
    return envs.length;
  }
}
