/**
 * A-06 · Trace 外发（Langfuse v3 ingestion API，HTTP 直连、零 SDK 依赖）。
 * 纪律（与项目红线一致）：
 * - **默认关闭**：未同时配置 host + public/secret key 时 enabled=false，零网络、零副作用，
 *   离线单测与冒烟不受影响（绝不为了"看起来接了"而默认外发）；
 * - **只外发元数据**：FallbackEvent 的结构化字段（layer/degraded_of/user_visible/时间）与
 *   Envelope 的 topic/ids/causation，绝不外发 trigger/action_taken 自由文本与任何业务正文；
 * - **失败不外溢**：网络错误只计数并记录原因分类，绝不抛异常打断业务链路（Trace 是旁路观察者）；
 * - **批量 + 显式 flush**：调用方决定何时发送；flush 结果如实回报 sent/failed。
 */
import type { Envelope } from "./envelope.js";
import type { FallbackEvent } from "./types.js";

export interface TraceSinkOptions {
  /** Langfuse 主机，如 http://127.0.0.1:3000 */
  url?: string;
  publicKey?: string;
  secretKey?: string;
  /** 测试注入；缺省 globalThis.fetch */
  fetchImpl?: typeof fetch;
  /** 单次 flush 的超时（毫秒），缺省 5000 */
  flushTimeoutMs?: number;
}

export interface TraceSinkStats {
  queued: number;
  sent: number;
  failed: number;
  /** 最近一次失败原因分类（不包含 URL 中的凭据/查询串） */
  last_error?: string;
}

interface IngestionItem {
  id: string;
  type: "trace-create" | "event-create";
  timestamp: string;
  body: Record<string, unknown>;
}

/** 环境变量名（兼容 .env.example 既有口径；SAFETRACE_ 前缀优先，便于多环境隔离）。 */
export const TRACE_ENV = {
  host: ["SAFETRACE_LANGFUSE_HOST", "LANGFUSE_HOST"],
  publicKey: ["SAFETRACE_LANGFUSE_PUBLIC_KEY", "LANGFUSE_PUBLIC_KEY"],
  secretKey: ["SAFETRACE_LANGFUSE_SECRET_KEY", "LANGFUSE_SECRET_KEY"],
} as const;

function pick(env: Record<string, string | undefined>, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return undefined;
}

export class LangfuseTraceSink {
  private readonly queue: IngestionItem[] = [];
  private sent = 0;
  private failed = 0;
  private lastError: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly opts: TraceSinkOptions = {}) {
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = opts.flushTimeoutMs ?? 5000;
  }

  /** 未配置 host/keys → 返回 null（调用方按"未启用"处理，禁止静默假装外发成功）。 */
  static fromEnv(env: Record<string, string | undefined> = process.env): LangfuseTraceSink | null {
    const url = pick(env, TRACE_ENV.host);
    const publicKey = pick(env, TRACE_ENV.publicKey);
    const secretKey = pick(env, TRACE_ENV.secretKey);
    if (!url || !publicKey || !secretKey) return null;
    return new LangfuseTraceSink({ url, publicKey, secretKey });
  }

  get enabled(): boolean {
    return Boolean(this.opts.url && this.opts.publicKey && this.opts.secretKey);
  }

  stats(): TraceSinkStats {
    return {
      queued: this.queue.length,
      sent: this.sent,
      failed: this.failed,
      ...(this.lastError ? { last_error: this.lastError } : {}),
    };
  }

  /** Envelope → trace-create（同一 trace_id 自然聚合；重复创建是幂等 upsert）。 */
  recordEnvelope(env: Envelope): void {
    if (!this.enabled) return;
    this.queue.push({
      id: env.event_id,
      type: "trace-create",
      timestamp: env.occurred_at,
      body: {
        id: env.trace_id,
        name: env.topic,
        metadata: { event_id: env.event_id, causation_id: env.causation_id, schema_version: env.schema_version },
      },
    });
  }

  /** FallbackEvent → event-create；只带结构化字段，不外发 trigger/action_taken 自由文本。 */
  recordFallbackEvent(event: FallbackEvent): void {
    if (!this.enabled) return;
    this.queue.push({
      id: event.event_id,
      type: "event-create",
      timestamp: event.degraded_state.since,
      body: {
        traceId: event.trace_id,
        name: "fallback." + event.layer,
        metadata: {
          event_id: event.event_id,
          layer: event.layer,
          degraded_of: event.degraded_of,
          user_visible: event.user_visible,
          degraded_state_label: event.degraded_state.label,
          detail_ref: event.degraded_state.detail_ref,
        },
      },
    });
  }

  /** 批量外发。任何失败都只计数，不抛出。 */
  async flush(): Promise<TraceSinkStats> {
    if (!this.enabled || this.queue.length === 0) return this.stats();
    const batch = this.queue.splice(0, this.queue.length);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const auth = "Basic " + Buffer.from(this.opts.publicKey + ":" + this.opts.secretKey, "utf8").toString("base64");
      const response = await this.fetchImpl(trimTrailingSlash(this.opts.url!) + "/api/public/ingestion", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: auth },
        body: JSON.stringify({ batch }),
        signal: controller.signal,
      });
      if (!response.ok) {
        this.failed += batch.length;
        this.lastError = "http_" + response.status;
      } else {
        this.sent += batch.length;
      }
    } catch (error) {
      this.failed += batch.length;
      this.lastError = error instanceof Error && error.name === "AbortError" ? "timeout" : "transport";
      // 旁路观察者：外发失败绝不向上抛，业务链路不依赖 Trace。
    } finally {
      clearTimeout(timer);
    }
    return this.stats();
  }
}

function trimTrailingSlash(url: string): string {
  let out = url;
  while (out.endsWith("/")) out = out.slice(0, -1);
  return out;
}
