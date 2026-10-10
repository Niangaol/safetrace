/**
 * A-06 常驻自愈守护进程核心（台账尾项：自愈只在演练里发生 → 挂到常驻进程）。
 *
 * 纪律：
 * - 与演练/冒烟共用同一个 SelfHealAgent（同一套工具白名单与退避参数），不造第二套自愈逻辑；
 * - start()：订阅 fallback.events（登记 + lineage + Trace 外发）+ 周期拍；
 * - 拍内容：dead_letter_drain（指数退避重投、成功销档）+ healthcheck 聚合；
 * - 每拍结果经 onTick 显式交出（守护进程落盘/看板消费），禁静默自愈；
 * - stop()：退净订阅与定时器（幂等）；拍串行，禁并发 drain。
 */
import type { EventBus, EventStore, LangfuseTraceSink } from "@safetrace/shared";
import { SelfHealAgent } from "./selfheal.js";
import type { BackoffOptions, CircuitSnapshot, DrainReport, SelfHealHealthReport } from "./selfheal.js";

export interface DaemonTickReport {
  /** 拍执行时间（ISO-8601 UTC）。 */
  at: string;
  drain: DrainReport;
  health: SelfHealHealthReport;
}

export interface SelfHealDaemonOptions {
  bus: EventBus;
  store: EventStore;
  /** 拍间隔（毫秒），缺省 60000（1 分钟）。 */
  intervalMs?: number;
  backoff?: BackoffOptions;
  /** MG1 熔断探针（生产由编排层注入 gateway breaker 集合；缺省 healthcheck 显式注明未观测）。 */
  circuits?: () => CircuitSnapshot[];
  traceSink?: LangfuseTraceSink | null;
  /** 注入时钟（测试确定性）。 */
  now?: () => number;
  /** 每拍观察者（守护进程落盘/看板）。 */
  onTick?: (report: DaemonTickReport) => void | Promise<void>;
}

export class SelfHealDaemon {
  /** 内置自愈 Agent（演练/冒烟/守护同一实现）；测试与运维可直接检查其登记簿。 */
  readonly agent: SelfHealAgent;
  private readonly opts: SelfHealDaemonOptions;
  private timer: ReturnType<typeof setInterval> | null = null;
  private unsubscribe: (() => void) | null = null;
  private ticking = false;
  /** 已执行拍数（运维观测）。 */
  ticks = 0;

  constructor(opts: SelfHealDaemonOptions) {
    this.opts = opts;
    this.agent = new SelfHealAgent({
      bus: opts.bus,
      store: opts.store,
      ...(opts.circuits ? { circuits: opts.circuits } : {}),
      ...(opts.traceSink !== undefined ? { traceSink: opts.traceSink } : {}),
      ...(opts.backoff ? { backoff: opts.backoff } : {}),
      ...(opts.now ? { now: opts.now } : {}),
    });
  }

  /** 常驻启动：订阅 fallback.events + 周期拍。重复 start 是幂等空操作。 */
  start(): void {
    if (this.timer) return;
    this.unsubscribe = this.agent.subscribeFallbackEvents();
    const interval = this.opts.intervalMs ?? 60_000;
    this.timer = setInterval(() => { void this.tick(); }, interval);
  }

  /** 单拍：drain 死信 + healthcheck + onTick。并发拍串行（ticking 闸门，禁并发 drain）。 */
  async tick(): Promise<DaemonTickReport> {
    if (this.ticking) throw new Error("上一拍尚未结束（自愈拍串行，禁并发 drain）");
    this.ticking = true;
    try {
      const drain = await this.agent.dead_letter_drain();
      const health = await this.agent.healthcheck();
      this.ticks += 1;
      const report: DaemonTickReport = { at: new Date((this.opts.now ?? Date.now)()).toISOString(), drain, health };
      await this.opts.onTick?.(report);
      return report;
    } finally {
      this.ticking = false;
    }
  }

  /** 停止：退净订阅与定时器（幂等）。已在执行的拍会跑完。 */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
  }
}