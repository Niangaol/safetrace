/**
 * MG1 Model Gateway（模型接入解耦层）。
 * 职责（02-report 第二节）：统一模型抽象 / provider 配置化切换 / 限流排队 /
 * 降级熔断 / token 计量。红线：业务代码只认 role；禁止 import provider SDK。
 */
import { degrade, type FallbackEvent } from "@safetrace/shared";
import { CircuitBreaker, type CircuitState } from "./circuit.js";
import { loadModelsConfig, type ModelProfile, type ModelsConfig, type RoleName } from "./profiles.js";
import { Semaphore, TokenBucket } from "./limiter.js";
import { cacheChat, hashEmbedding, hashRerank } from "./providers/cache.js";
import { compatChat, compatEmbed, compatRerankUnsupported, OpenAiCompatError, resolveConfig } from "./providers/openai-compat.js";
import { MemoryUsageStore, SqliteUsageStore, type UsageStore } from "./usage-store.js";
import type { ChatMessage, ChatParams, Embedding, LlmReply, RankedDocs } from "./types.js";

export interface GatewayOptions {
  configPath?: string;
  usageStore?: UsageStore;
  /** 强制所有 role 使用指定 provider（演练用：验证切配置不改代码） */
  forceProvider?: string;
  /** FallbackEvent 出口（总线）；缺省仅内部计数 */
  onFallback?: (event: FallbackEvent) => void | Promise<void>;
  /** 注入 fetch（测试用） */
  fetchImpl?: typeof fetch;
}

interface RoleRuntime {
  profile: ModelProfile;
  bucket: TokenBucket;
  semaphore: Semaphore;
  breakers: Map<string, CircuitBreaker>;
}

export class ModelGateway {
  private cfg: ModelsConfig;
  private runtime = new Map<RoleName, RoleRuntime>();
  private usage: UsageStore;
  /** 归一化 prompt 缓存：模型故障时提供兜底答案（L3） */
  private cache = new Map<string, LlmReply>();

  constructor(private opts: GatewayOptions = {}) {
    this.cfg = loadModelsConfig(opts.configPath);
    this.usage = opts.usageStore ?? new MemoryUsageStore();
    for (const [name, profile] of Object.entries(this.cfg.roles)) {
      this.runtime.set(name as RoleName, {
        profile,
        bucket: new TokenBucket(Math.max(1, profile.max_rpm), profile.max_rpm),
        semaphore: new Semaphore(Math.max(1, profile.max_concurrency)),
        breakers: new Map(),
      });
    }
  }

  /** 模型角色清单（对外只暴露 role 名，不见厂商）。 */
  roles(): Array<{ role: RoleName; provider: string; model_id: string; fallback_chain: string[] }> {
    return [...this.runtime.entries()].map(([role, rt]) => ({
      role,
      provider: rt.profile.provider,
      model_id: rt.profile.model_id,
      fallback_chain: rt.profile.fallback_chain,
    }));
  }

  /** 熔断状态快照（A1 消费）。 */
  circuitStates(): CircuitState[] {
    const out: CircuitState[] = [];
    for (const [role, rt] of this.runtime) {
      for (const [provider, br] of rt.breakers) {
        out.push(br.state());
      }
      if (rt.breakers.size === 0) {
        out.push({ key: role + "/" + rt.profile.provider, status: "closed", opened_at: null, consecutive_failures: 0, reason: null });
      }
    }
    return out;
  }

  /** 用量查询（token 计量与降级统计）。 */
  usageQuery(filter?: { role?: string; provider?: string }) {
    return this.usage.query(filter);
  }

  usageTotals() {
    return this.usage.totals();
  }

  async chat(role: RoleName, messages: ChatMessage[], params: ChatParams = {}, traceId = "tr_ad-hoc"): Promise<LlmReply> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    const t0 = Date.now();
    try {
      return await this.withFallback<LlmReply>(role, "chat", async (providerName, modelId) => {
        const key = role + "|" + providerName + "|" + modelId + "|" + normalizePrompt(messages);
        const hit = this.cache.get(key);
        if (hit) {
          return { ...hit, cached: true, degraded_to: "", latency_ms: Date.now() - t0 };
        }
        const out = await this.callChat(providerName, modelId, rt, messages, params);
        this.cache.set(key, out);
        return out;
      }, traceId);
    } finally {
      release();
    }
  }

  async embed(role: RoleName, texts: string[], traceId = "tr_ad-hoc"): Promise<Embedding> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    try {
      return await this.withFallback<Embedding>(role, "embed", async (providerName, modelId) => {
        if (providerName === "cache") {
          const dim = Number(rt.profile.capability_flags.dim ?? 256);
          return { vectors: texts.map((t) => hashEmbedding(t, dim)), model_id: modelId, provider: providerName, degraded_to: "" };
        }
        const def = this.cfg.providers[providerName];
        if (!def) throw new Error("未知 provider: " + providerName);
        const cfg = resolveConfig(def, modelId, rt.profile.timeout_ms);
        const vectors = await compatEmbed(cfg, texts);
        return { vectors, model_id: modelId, provider: providerName, degraded_to: "" };
      }, traceId);
    } finally {
      release();
    }
  }

  async rerank(role: RoleName, query: string, docs: string[], traceId = "tr_ad-hoc"): Promise<RankedDocs> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    try {
      return await this.withFallback<RankedDocs>(role, "rerank", async (providerName, modelId) => {
        if (providerName === "cache") {
          return { ranked: hashRerank(query, docs), model_id: modelId, provider: providerName, degraded_to: "" };
        }
        const def = this.cfg.providers[providerName];
        if (!def) throw new Error("未知 provider: " + providerName);
        if (def.capability_flags?.rerank === false) {
          // 能力缺失显式报错（禁静默降级成 chat 冒充 rerank）
          compatRerankUnsupported(providerName);
        }
        throw new OpenAiCompatError("openai_compat provider 暂无标准 rerank 端点，请配置本地 bge-reranker 服务");
      }, traceId);
    } finally {
      release();
    }
  }

  private async callChat(
    providerName: string,
    modelId: string,
    rt: RoleRuntime,
    messages: ChatMessage[],
    params: ChatParams,
  ): Promise<LlmReply> {
    const t0 = Date.now();
    if (providerName === "cache" || providerName === "template") {
      const out = cacheChat(messages, modelId);
      return { ...out, model_id: modelId, provider: providerName, latency_ms: Date.now() - t0, cached: false, degraded_to: "" };
    }
    const def = this.cfg.providers[providerName];
    if (!def) throw new Error("未知 provider: " + providerName);
    const cfg = resolveConfig(def, modelId, rt.profile.timeout_ms);
    const out = await compatChat(cfg, messages, params);
    return { ...out, model_id: modelId, provider: providerName, latency_ms: Date.now() - t0, cached: false, degraded_to: "" };
  }

  /**
   * 降级链执行：按 profile.fallback_chain 顺序尝试；
   * - 熔断中的 provider 快速跳过；
   * - 全部失败 → 最后一级强制 cache（L3）并登记 FallbackEvent；
   * - 非首选 provider 成功 → degraded_to 显式标注（禁静默）。
   */
  private async withFallback<T extends { degraded_to: string; provider: string }>(
    role: RoleName,
    call: "chat" | "embed" | "rerank",
    fn: (providerName: string, modelId: string) => Promise<T>,
    traceId: string,
  ): Promise<T> {
    const rt = this.mustRole(role);
    const chain = this.opts.forceProvider
      ? [this.opts.forceProvider, ...rt.profile.fallback_chain]
      : [rt.profile.provider, ...rt.profile.fallback_chain];
    const seen = new Set<string>();
    const ordered = chain.filter((p) => (seen.has(p) ? false : (seen.add(p), true)));

    let lastError: unknown = null;
    for (let i = 0; i < ordered.length; i += 1) {
      const providerName = ordered[i]!;
      const isPrimary = i === 0;
      const br = this.breakerFor(role, providerName);
      if (!br.allow()) {
        lastError = new Error("provider " + providerName + " 熔断中");
        continue;
      }
      const modelId = providerName === rt.profile.provider ? rt.profile.model_id : providerName + "-fallback";
      try {
        const result = await fn(providerName, modelId);
        br.onSuccess();
        await this.record(role, call, providerName, modelId, result, traceId);
        if (!isPrimary) {
          // 非首选 provider 成功 = 显式降级，登记 FallbackEvent
          const d = await degrade({
            layer: "L3",
            trigger: "首选 provider 不可用，切换至 " + providerName,
            degradedOf: providerName,
            traceId,
            label: "模型服务降级通道：" + providerName,
            emit: this.opts.onFallback,
          });
          return { ...result, degraded_to: d.degraded_to };
        }
        return result;
      } catch (err) {
        br.onFailure();
        lastError = err;
      }
    }

    // 全链失败：强制 cache 兜底（L3），显式标记
    const modelId = rt.profile.model_id;
    const result = await fn("cache", modelId);
    const d = await degrade({
      layer: "L3",
      trigger: "fallback_chain 全链失败: " + (lastError instanceof Error ? lastError.message : String(lastError)),
      degradedOf: "cache",
      traceId,
      label: "模型服务全链降级为缓存通道（答案可能陈旧）",
      recoveryHint: "检查 provider 配置与网络；恢复后熔断自动关闭",
      emit: this.opts.onFallback,
    });
    await this.record(role, call, "cache", modelId, result, traceId);
    return { ...result, degraded_to: d.degraded_to };
  }

  private async record(role: RoleName, call: "chat" | "embed" | "rerank", provider: string, modelId: string, result: { usage?: { prompt_tokens: number; completion_tokens: number }; degraded_to: string }, traceId: string): Promise<void> {
    await this.usage.record({
      ts: new Date().toISOString(),
      role,
      provider,
      model_id: modelId,
      call,
      prompt_tokens: result.usage?.prompt_tokens ?? 0,
      completion_tokens: result.usage?.completion_tokens ?? 0,
      latency_ms: 0,
      cached: false,
      degraded_to: result.degraded_to,
      trace_id: traceId,
    });
  }

  private breakerFor(role: RoleName, provider: string): CircuitBreaker {
    const rt = this.mustRole(role);
    let br = rt.breakers.get(provider);
    if (!br) {
      br = new CircuitBreaker(role + "/" + provider);
      rt.breakers.set(provider, br);
    }
    return br;
  }

  private mustRole(role: RoleName): RoleRuntime {
    const rt = this.runtime.get(role);
    if (!rt) throw new Error("未配置的模型角色: " + role);
    return rt;
  }
}

/** 归一化 prompt：缓存键（去空白、小写）。 */
function normalizePrompt(messages: ChatMessage[]): string {
  return messages.map((m) => m.role + ":" + m.content.trim().toLowerCase()).join("\n");
}

export { loadModelsConfig };
export type { ModelProfile, ModelsConfig, RoleName };
export { MemoryUsageStore, SqliteUsageStore };
export type { UsageStore };
