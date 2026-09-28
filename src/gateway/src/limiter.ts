/**
 * MG1 限流：令牌桶（RPM）+ 并发闸门。超限请求进队列等待而非直接失败（削峰语义）。
 */
export class TokenBucket {
  private tokens: number;
  private last: number;

  constructor(
    private readonly capacity: number,
    private readonly refillPerMinute: number,
    now = Date.now(),
  ) {
    this.tokens = capacity;
    this.last = now;
  }

  private refill(now: number): void {
    const elapsedMin = (now - this.last) / 60000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedMin * this.refillPerMinute);
    this.last = now;
  }

  /** 尝试取 n 个令牌；不足返回需等待毫秒数（0 表示已取到）。 */
  tryTake(n = 1, now = Date.now()): number {
    this.refill(now);
    if (this.tokens >= n) {
      this.tokens -= n;
      return 0;
    }
    const deficit = n - this.tokens;
    return Math.ceil((deficit / this.refillPerMinute) * 60000);
  }

  /** 取令牌（必要时等待），返回实际等待毫秒。 */
  async take(n = 1): Promise<number> {
    const t0 = Date.now();
    for (;;) {
      const wait = this.tryTake(n);
      if (wait === 0) return Date.now() - t0;
      await sleep(Math.min(wait, 250));
    }
  }
}

/** 并发信号量：max_concurrency。 */
export class Semaphore {
  private active = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(): Promise<() => void> {
    if (this.active < this.max) {
      this.active += 1;
      return () => this.release();
    }
    await new Promise<void>((res) => this.queue.push(res));
    this.active += 1;
    return () => this.release();
  }

  private release(): void {
    this.active -= 1;
    const next = this.queue.shift();
    if (next) next();
  }

  get inFlight(): number {
    return this.active;
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
