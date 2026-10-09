/**
 * A-06 · A1 自愈 Agent（对应 roles.ts selfheal 角色与 FB1 多层兜底）。
 * 落地范围（台账 A-06）：
 * - 订阅 fallback.events：登记全部降级事件（兜底透明率 100% 的证据源）并外发 Trace；
 * - 死信指数退避重投（L1 重试幂等 / L2 恢复的代码侧抓手）：redeliver 成功即销档；
 * - healthcheck 聚合：死信、退避队列、fallback 统计、MG1 熔断状态、Trace 外发统计；
 * - drill：检测→降级→退避→恢复→重放→验证 全链路演练（自愈演练录像的证据生产器）。
 *
 * 纪律：
 * - 自愈动作全部显式留痕（lineage + Trace），禁止静默恢复；
 * - 三工具与角色白名单逐一对应，越权工具直接抛错（权限边界）；
 * - 重投节拍由注入时钟驱动（测试确定性），生产默认指数退避 base 1s、上限 5min、最多 8 次。
 */
import { degrade } from "@safetrace/shared";
import type { Envelope, EventBus, EventStore, FallbackEvent, LangfuseTraceSink, Topic } from "@safetrace/shared";

/** 熔断状态快照（MG1 CircuitBreaker.state() 的结构化投影；未注入时 healthcheck 显式注明未观测）。 */
export interface CircuitSnapshot {
  key: string;
  status: "closed" | "open" | "half_open";
  opened_at: string | null;
  consecutive_failures: number;
  reason: string | null;
}

/** selfheal 角色三工具的最小权限集（对齐 contracts ToolPermissions 形状；S4 热注册的数据源）。 */
export const SELFHEAL_TOOL_PERMISSIONS = {
  replay: { network: false, filesystem: "none", exec: false },
  dead_letter_drain: { network: false, filesystem: "none", exec: false },
  healthcheck: { network: false, filesystem: "none", exec: false },
} as const;

export type SelfHealToolName = keyof typeof SELFHEAL_TOOL_PERMISSIONS;

/** 工具白名单边界：未知/越权工具直接抛错（禁静默忽略）。 */
export function assertSelfhealTool(name: string): asserts name is SelfHealToolName {
  if (!(name in SELFHEAL_TOOL_PERMISSIONS)) {
    throw new Error("selfheal 角色无权使用工具：" + name + "（白名单：" + Object.keys(SELFHEAL_TOOL_PERMISSIONS).join("/") + "）");
  }
}

export interface BackoffOptions {
  /** 首次重投等待（毫秒），缺省 1000 */
  baseMs?: number;
  /** 退避上限（毫秒），缺省 300000 */
  maxMs?: number;
  /** 同一死信最多重投次数，超过则保留死信转人工，缺省 8 */
  maxAttempts?: number;
}

export interface SelfHealOptions {
  bus: EventBus;
  store: EventStore;
  /** MG1 熔断状态探针（生产由编排层注入 gateway 的 breaker 集合） */
  circuits?: () => CircuitSnapshot[];
  /** Trace 外发（未配置 = 未启用；selfheal 不替调用方决定外发） */
  traceSink?: LangfuseTraceSink | null;
  backoff?: BackoffOptions;
  /** 注入时钟（测试确定性） */
  now?: () => number;
  /** 单次 drain 最多处理多少条死信（缺省 50，防止长尾拖垮一轮） */
  drainLimit?: number;
}

export interface DeadLetterRetryRecord {
  event_id: string;
  topic: Topic;
  attempt: number;
  next_attempt_at: number;
  last_error?: string;
}

export interface DrainReport {
  examined: number;
  retried: number;
  recovered: number;
  deferred: number;
  still_failed: number;
  details: Array<{ event_id: string; topic: Topic; attempt: number; outcome: "recovered" | "deferred" | "still_failed" }>;
}

export interface SelfHealHealthReport {
  status: "ok" | "degraded";
  checked_at: string;
  dead_letters: number;
  retry_scheduled: number;
  fallback_events: {
    total: number;
    by_layer: Record<string, number>;
    by_degraded_of: Record<string, number>;
  };
  circuits: CircuitSnapshot[];
  circuits_observed: boolean;
  trace: { enabled: boolean; queued: number; sent: number; failed: number };
  notes: string[];
}

export interface DrillStep {
  step: string;
  ok: boolean;
  detail: string;
}

export interface DrillReport {
  ok: boolean;
  steps: DrillStep[];
  health: SelfHealHealthReport;
  drain: DrainReport;
}

export class SelfHealAgent {
  /** 登记到的全部降级事件（兜底透明率 100% 的证据） */
  readonly registeredFallbackEvents: FallbackEvent[] = [];
  /** 总线 onDeadLetter 通知（与 store 死信表双视图） */
  readonly deadLetterNotifications: Array<{ event_id: string; reason: string; at: string }> = [];

  private readonly retries = new Map<string, DeadLetterRetryRecord>();
  private unsubscribe: (() => void) | null = null;

  constructor(private readonly opts: SelfHealOptions) {}

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  private backoffMs(attempt: number): number {
    const base = this.opts.backoff?.baseMs ?? 1000;
    const max = this.opts.backoff?.maxMs ?? 300_000;
    return Math.min(max, base * Math.pow(2, Math.max(0, attempt - 1)));
  }

  /** 订阅 fallback.events：登记 + lineage + Trace 外发（兜底透明率 100%）。 */
  subscribeFallbackEvents(): () => void {
    if (this.unsubscribe) return this.unsubscribe;
    this.unsubscribe = this.opts.bus.subscribe("fallback.events", async (payload: FallbackEvent, env: Envelope<FallbackEvent>) => {
      this.registeredFallbackEvents.push(payload);
      await this.opts.bus.recordLineage({
        trace_id: payload.trace_id,
        causation_id: payload.event_id,
        stage: "selfheal.fallback_registration",
        operation_version: "selfheal.v1",
        status: "degraded",
        input_refs: [{ kind: "FallbackEvent", id: payload.event_id }],
        decision: { fallback_to: payload.degraded_of, reason: "layer " + payload.layer },
      });
      this.opts.traceSink?.recordEnvelope(env);
      this.opts.traceSink?.recordFallbackEvent(payload);
    });
    return this.unsubscribe;
  }

  /** 总线死信通知入口（由调用方在 BusOptions.onDeadLetter 接线）。 */
  noteDeadLetter(eventId: string, reason: string): void {
    this.deadLetterNotifications.push({ event_id: eventId, reason, at: new Date(this.now()).toISOString() });
  }

  /** 工具 replay：按主题重读并重新投递（死信修复后的整 topic 恢复手段）。 */
  async replay(topic: Topic, opts: { offset?: number; limit?: number; traceId?: string } = {}): Promise<{ replayed: number }> {
    assertSelfhealTool("replay");
    const replayed = await this.opts.bus.replay(topic, opts.offset ?? 0, opts.limit ?? 100);
    await this.opts.bus.recordLineage({
      trace_id: opts.traceId ?? "tr_selfheal_replay_" + this.now().toString(36),
      stage: "selfheal.replay",
      operation_version: "selfheal.v1",
      status: "success",
      input_refs: [{ kind: "Topic", id: topic }],
      output_refs: [{ kind: "ReplayedEvents", id: topic, sha256: undefined }],
      decision: { reason: "replayed " + replayed + " event(s)" },
    });
    return { replayed };
  }

  /** 工具 dead_letter_drain：指数退避重投；成功销档，失败保留并排下一拍。 */
  async dead_letter_drain(opts: { now?: number } = {}): Promise<DrainReport> {
    assertSelfhealTool("dead_letter_drain");
    const now = opts.now ?? this.now();
    const dead = await this.opts.store.deadLetters();
    const report: DrainReport = { examined: 0, retried: 0, recovered: 0, deferred: 0, still_failed: 0, details: [] };
    const limit = this.opts.drainLimit ?? 50;
    for (const entry of dead.slice(0, limit)) {
      report.examined += 1;
      const rec: DeadLetterRetryRecord = this.retries.get(entry.event_id) ?? {
        event_id: entry.event_id,
        topic: entry.envelope.topic,
        attempt: 0,
        next_attempt_at: 0,
      };
      if (rec.next_attempt_at > now) {
        report.deferred += 1;
        report.details.push({ event_id: entry.event_id, topic: rec.topic, attempt: rec.attempt, outcome: "deferred" });
        continue;
      }
      report.retried += 1;
      const ok = await this.opts.bus.redeliver(entry.envelope as Envelope);
      rec.attempt += 1;
      if (ok) {
        report.recovered += 1;
        report.details.push({ event_id: entry.event_id, topic: rec.topic, attempt: rec.attempt, outcome: "recovered" });
        this.retries.delete(entry.event_id);
      } else {
        rec.last_error = entry.reason;
        rec.next_attempt_at = now + this.backoffMs(rec.attempt);
        const maxAttempts = this.opts.backoff?.maxAttempts ?? 8;
        const exhausted = rec.attempt >= maxAttempts;
        if (exhausted) {
          report.still_failed += 1;
          report.details.push({ event_id: entry.event_id, topic: rec.topic, attempt: rec.attempt, outcome: "still_failed" });
        } else {
          report.deferred += 1;
          report.details.push({ event_id: entry.event_id, topic: rec.topic, attempt: rec.attempt, outcome: "deferred" });
        }
        this.retries.set(entry.event_id, rec);
      }
    }
    await this.opts.bus.recordLineage({
      trace_id: "tr_selfheal_drain_" + now.toString(36),
      stage: "selfheal.dead_letter_drain",
      operation_version: "selfheal.v1",
      status: report.still_failed > 0 ? "degraded" : "success",
      input_refs: [{ kind: "DeadLetterQueue", id: "dead_letters" }],
      output_refs: [{ kind: "DrainReport", id: "drain", sha256: undefined }],
      decision: {
        reason: "examined=" + report.examined + " retried=" + report.retried + " recovered=" + report.recovered +
          " deferred=" + report.deferred + " still_failed=" + report.still_failed,
        ...(report.still_failed > 0 ? { review_required: true } : {}),
      },
    });
    return report;
  }

  /** 工具 healthcheck：聚合死信 / 退避队列 / fallback 统计 / 熔断状态 / Trace 外发。 */
  async healthcheck(): Promise<SelfHealHealthReport> {
    assertSelfhealTool("healthcheck");
    const dead = await this.opts.store.deadLetters();
    const byLayer: Record<string, number> = {};
    const byDegradedOf: Record<string, number> = {};
    for (const event of this.registeredFallbackEvents) {
      byLayer[event.layer] = (byLayer[event.layer] ?? 0) + 1;
      byDegradedOf[event.degraded_of] = (byDegradedOf[event.degraded_of] ?? 0) + 1;
    }
    const circuits = this.opts.circuits ? this.opts.circuits() : [];
    const traceStats = this.opts.traceSink?.stats();
    const notes: string[] = [];
    if (dead.length > 0) notes.push("存在 " + dead.length + " 条死信待重投或人工处理");
    if (this.retries.size > 0) notes.push(this.retries.size + " 条死信处于指数退避等待");
    if (!this.opts.circuits) notes.push("未注入熔断探针：L4 熔断状态本轮不可观测（显式注明，不冒充健康）");
    if (!this.opts.traceSink) notes.push("未配置 Trace 外发：自愈动作只落本地 lineage");
    const openCircuits = circuits.filter((c) => c.status !== "closed");
    if (openCircuits.length > 0) notes.push(openCircuits.length + " 个 provider 处于非 closed 熔断状态");
    return {
      status: dead.length > 0 || openCircuits.length > 0 ? "degraded" : "ok",
      checked_at: new Date(this.now()).toISOString(),
      dead_letters: dead.length,
      retry_scheduled: this.retries.size,
      fallback_events: { total: this.registeredFallbackEvents.length, by_layer: byLayer, by_degraded_of: byDegradedOf },
      circuits,
      circuits_observed: Boolean(this.opts.circuits),
      trace: {
        enabled: Boolean(this.opts.traceSink?.enabled),
        queued: traceStats?.queued ?? 0,
        sent: traceStats?.sent ?? 0,
        failed: traceStats?.failed ?? 0,
      },
      notes,
    };
  }

  /**
   * 自愈演练：检测→降级→故障注入→重投失败→指数退避→恢复→重放销档→验证。
   * 传入注入的"故障消费者/恢复消费者"挂钩，全部在调用方自己的 store/bus 内闭环，不碰生产数据。
   */
  async drill(hooks: {
    /** 制造一次消费失败（返回订阅取消函数） */
    breakConsumer: () => () => void;
    /** 恢复后的消费者（应成功处理重放事件） */
    fixConsumer: () => () => void;
    /** 演练用事件的发布（返回发布的事件） */
    publishDrillEvent: () => Promise<Envelope>;
  }): Promise<DrillReport> {
    const steps: DrillStep[] = [];
    const push = (step: string, ok: boolean, detail: string) => { steps.push({ step, ok, detail }); };

    // 1) 检测：基线健康检查
    const baseline = await this.healthcheck();
    push("detect", true, "baseline dead_letters=" + baseline.dead_letters + " fallback_events=" + baseline.fallback_events.total);

    // 2) 降级：登记一次显式降级（fallback.events → selfheal 登记 + Trace）
    const before = this.registeredFallbackEvents.length;
    await degrade({
      layer: "L1",
      trigger: "selfheal drill: simulated consumer failure",
      degradedOf: "drill:simulated-consumer",
      traceId: "tr_selfheal_drill",
      label: "自愈演练：模拟消费者失败（显式降级）",
      recoveryHint: "重放死信即可恢复",
      emit: async (event) => { await this.opts.bus.publish("fallback.events", event, { trace_id: event.trace_id }); },
    });
    push("degrade", this.registeredFallbackEvents.length === before + 1,
      "fallback.events 已登记（" + this.registeredFallbackEvents.length + " 条，兜底透明率 100%）");

    // 3) 故障注入：坏消费者 + 发布 → 事件进死信队列（坏消费者持续订阅到退避演示结束）
    const releaseBreak = hooks.breakConsumer();
    const drillEnvelope = await hooks.publishDrillEvent();
    const deadAfterBreak = await this.opts.store.deadLetters();
    const broken = deadAfterBreak.some((d) => d.event_id === drillEnvelope.event_id);
    push("inject-failure", broken, "事件 " + drillEnvelope.event_id + " 进入死信队列（共 " + deadAfterBreak.length + " 条）");

    // 4) 重投失败：消费者仍坏 → 记 attempt 并按指数退避排下一拍
    const now = this.now();
    const firstDrain = await this.dead_letter_drain({ now });
    const failedRetry = firstDrain.details.some((d) => d.event_id === drillEnvelope.event_id && d.outcome === "deferred" && d.attempt >= 1);
    push("retry-fails", firstDrain.retried >= 1 && firstDrain.recovered === 0 && failedRetry,
      "首次重投失败（retried=" + firstDrain.retried + " recovered=" + firstDrain.recovered + "）");

    // 5) 指数退避：同一拍号再 drain → 不重投（等待窗口生效）
    const backoffDrain = await this.dead_letter_drain({ now });
    const deferredInWindow = backoffDrain.details.some((d) => d.event_id === drillEnvelope.event_id && d.outcome === "deferred");
    push("backoff", backoffDrain.retried === 0 && deferredInWindow,
      "退避窗口内不重投（retried=" + backoffDrain.retried + " deferred=" + backoffDrain.deferred + "）");

    // 6) 恢复 + 重放：修复消费者（先摘除坏消费者），到拍重投 → 成功销档
    releaseBreak();
    const releaseFix = hooks.fixConsumer();
    const drain = await this.dead_letter_drain({ now: now + this.backoffMs(1) + 1 });
    const recovered = drain.details.some((d) => d.event_id === drillEnvelope.event_id && d.outcome === "recovered");
    releaseFix();
    push("recover", recovered && drain.recovered >= 1,
      "死信重投成功并销档（recovered=" + drain.recovered + "）");

    // 7) 验证：死信清零 + fallback 登记不丢 + Trace 外发统计（先 flush 再出报告，数字不虚）
    const trace = this.opts.traceSink;
    if (trace?.enabled) await trace.flush();
    const health = await this.healthcheck();
    const traceOk = !trace || !trace.enabled || trace.stats().sent > 0;
    push("verify", health.dead_letters === 0 && health.fallback_events.total >= before + 1 && traceOk,
      "dead_letters=" + health.dead_letters + " fallback_events=" + health.fallback_events.total +
        " trace(sent=" + health.trace.sent + ",failed=" + health.trace.failed + ")");

    return { ok: steps.every((s) => s.ok), steps, health, drain };
  }
}
