/**
 * 熔断器（MG1 职责 4）：provider 连续失败超阈即熔断，OPEN 期间快速失败，
 * 半开状态放一个探针请求。状态以 CircuitState 暴露给 A1。
 */
export type CircuitStatus = "closed" | "open" | "half_open";

export interface CircuitState {
  key: string;
  status: CircuitStatus;
  opened_at: string | null;
  consecutive_failures: number;
  reason: string | null;
}

export interface CircuitOptions {
  /** 连续失败多少次触发熔断 */
  failureThreshold?: number;
  /** OPEN 状态持续毫秒后进半开 */
  openMs?: number;
  now?: () => number;
}

export class CircuitBreaker {
  private failures = 0;
  private openedAt: number | null = null;
  private halfOpenProbeUsed = false;

  constructor(
    private readonly key: string,
    private readonly opts: CircuitOptions = {},
  ) {}

  private get threshold(): number {
    return this.opts.failureThreshold ?? 5;
  }

  private get openMs(): number {
    return this.opts.openMs ?? 60000;
  }

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  state(): CircuitState {
    const t = this.now();
    if (this.openedAt !== null) {
      const elapsed = t - this.openedAt;
      if (elapsed < this.openMs) {
        return { key: this.key, status: "open", opened_at: new Date(this.openedAt).toISOString(), consecutive_failures: this.failures, reason: "failure_threshold_exceeded" };
      }
      // 探针期：无论探针是否已用，状态都是 half_open（allow() 决定放行哪个探针）
      return { key: this.key, status: "half_open", opened_at: new Date(this.openedAt).toISOString(), consecutive_failures: this.failures, reason: "half_open_probe" };
    }
    return { key: this.key, status: "closed", opened_at: null, consecutive_failures: this.failures, reason: null };
  }

  /** 是否允许放行（半开只放一个探针）。 */
  allow(): boolean {
    const s = this.state();
    if (s.status === "closed") return true;
    if (s.status === "half_open") {
      if (this.halfOpenProbeUsed) return false;
      this.halfOpenProbeUsed = true;
      return true;
    }
    return false;
  }

  onSuccess(): void {
    this.failures = 0;
    this.openedAt = null;
    this.halfOpenProbeUsed = false;
  }

  onFailure(): void {
    this.failures += 1;
    // A failed half-open probe starts a new cooldown and releases the probe slot.
    if (this.failures >= this.threshold && (this.openedAt === null || this.halfOpenProbeUsed)) {
      this.openedAt = this.now();
      this.halfOpenProbeUsed = false;
    }
  }
}
