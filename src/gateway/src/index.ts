/**
 * MG1 Model Gateway（模型接入解耦层）。
 * 职责（02-report 第二节）：统一模型抽象 / provider 配置化切换 / 限流排队 /
 * 降级熔断 / token 计量。红线：业务代码只认 role；禁止 import provider SDK。
 */
import { degrade, nowIso, sha256Json } from "@safetrace/shared";
import type { EventBus, FallbackEvent, LineageArtifactRef } from "@safetrace/shared";
import { CircuitBreaker, type CircuitState } from "./circuit.js";
import { loadModelsConfig, type DataDomain, type ModelProfile, type ModelsConfig, type RoleName } from "./profiles.js";
import { Semaphore, TokenBucket } from "./limiter.js";
import { cacheChat, hashEmbedding, hashRerank } from "./providers/cache.js";
import { compatChat, compatEmbed, compatRerankUnsupported, OpenAiCompatError, resolveConfig } from "./providers/openai-compat.js";
import { MemoryUsageStore, SqliteUsageStore, type UsageStore } from "./usage-store.js";
import type { ChatMessage, ChatParams, Embedding, LlmReply, RankedDocs } from "./types.js";

export interface GatewayOptions {
  configPath?: string;
  usageStore?: UsageStore;
  /** Persistent per-attempt lineage sink; production callers should inject the shared EventBus. */
  bus?: EventBus;
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

function assertEmbeddingVectors(vectors: number[][], count: number, expectedDim?: number): void {
  if (!Array.isArray(vectors) || vectors.length !== count) throw new Error("embedding 返回数量与输入不一致");
  const dim = vectors[0]?.length ?? 0;
  if (dim <= 0 || (expectedDim !== undefined && dim !== expectedDim)) throw new Error("embedding 维度与角色配置不一致");
  for (const vector of vectors) {
    if (vector.length !== dim || vector.some((value) => typeof value !== "number" || !Number.isFinite(value))) {
      throw new Error("embedding 含空向量、维度不一致或非有限数值");
    }
  }
}

/**
 * 计量所需公共字段：latency_ms / cached 必须随调用结果一起回传，
 * 由 record() 原样落库——禁止在 record 层写死（R-03：写死 0/false 会丢失真实值，
 * "降级与缓存统计"直接失真）。usage 仅 chat 有，embed/rerank 记为 0。
 */
interface MeteredResult {
  degraded_to: string;
  latency_ms: number;
  cached: boolean;
  usage?: { prompt_tokens: number; completion_tokens: number };
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

  /** Embedder 的集合建集元数据；维度必须与模型实际返回保持一致。 */
  embeddingProfile(): { provider: string; model_id: string; model_version: string; dimension?: number } {
    const profile = this.mustRole("embedder").profile;
    const rawDimension = profile.capability_flags.dim;
    const dimension = typeof rawDimension === "number" && Number.isInteger(rawDimension) && rawDimension > 0
      ? rawDimension
      : undefined;
    return {
      provider: profile.provider,
      model_id: profile.model_id,
      model_version: profile.model_version,
      ...(dimension === undefined ? {} : { dimension }),
    };
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

  async chat(role: RoleName, messages: ChatMessage[], params: ChatParams = {}, traceId = "tr_ad-hoc", dataDomain?: DataDomain): Promise<LlmReply> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    const t0 = Date.now();
    const requestedDomain = dataDomain ?? rt.profile.data_domain ?? "public";
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
      }, traceId, [{ kind: "ChatMessages", id: traceId, sha256: sha256Json({ messages, params }) }], requestedDomain);
    } finally {
      release();
    }
  }

  async embed(role: RoleName, texts: string[], traceId = "tr_ad-hoc", dataDomain?: DataDomain): Promise<Embedding> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    const t0 = Date.now();
    const requestedDomain = dataDomain ?? rt.profile.data_domain ?? "public";
    const rawDim = rt.profile.capability_flags.dim;
    const expectedDim = typeof rawDim === "number" && Number.isInteger(rawDim) && rawDim > 0 ? rawDim : undefined;
    try {
      return await this.withFallback<Embedding>(role, "embed", async (providerName, modelId) => {
        if (providerName === "cache") {
          const dim = expectedDim ?? 256;
          const vectors = texts.map((text) => hashEmbedding(text, dim));
          assertEmbeddingVectors(vectors, texts.length, dim);
          return { vectors, model_id: modelId, model_version: rt.profile.model_version, provider: providerName, latency_ms: Date.now() - t0, cached: false, degraded_to: "" };
        }
        const def = this.cfg.providers[providerName];
        if (!def) throw new Error("未知 provider: " + providerName);
        const cfg = resolveConfig(def, modelId, rt.profile.timeout_ms);
        const vectors = await compatEmbed(cfg, texts);
        assertEmbeddingVectors(vectors, texts.length, expectedDim);
        return { vectors, model_id: modelId, model_version: rt.profile.model_version, provider: providerName, latency_ms: Date.now() - t0, cached: false, degraded_to: "" };
      }, traceId, [{ kind: "EmbeddingBatch", id: traceId, sha256: sha256Json(texts) }], requestedDomain);
    } finally {
      release();
    }
  }

  async rerank(role: RoleName, query: string, docs: string[], traceId = "tr_ad-hoc"): Promise<RankedDocs> {
    const rt = this.mustRole(role);
    await rt.bucket.take(1);
    const release = await rt.semaphore.acquire();
    const t0 = Date.now();
    try {
      return await this.withFallback<RankedDocs>(role, "rerank", async (providerName, modelId) => {
        if (providerName === "cache") {
          return { ranked: hashRerank(query, docs), model_id: modelId, provider: providerName, latency_ms: Date.now() - t0, cached: false, degraded_to: "" };
        }
        const def = this.cfg.providers[providerName];
        if (!def) throw new Error("未知 provider: " + providerName);
        if (def.capability_flags?.rerank === false) {
          // 能力缺失显式报错（禁静默降级成 chat 冒充 rerank）
          compatRerankUnsupported(providerName);
        }
        throw new OpenAiCompatError("openai_compat provider 暂无标准 rerank 端点，请配置本地 bge-reranker 服务");
      }, traceId, [{ kind: "RerankRequest", id: traceId, sha256: sha256Json({ query, docs }) }]);
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
  private async withFallback<T extends MeteredResult & { provider: string }>(
    role: RoleName,
    call: "chat" | "embed" | "rerank",
    fn: (providerName: string, modelId: string) => Promise<T>,
    traceId: string,
    inputRefs: LineageArtifactRef[],
    requestedDomain: DataDomain = "public",
  ): Promise<T> {
    const rt = this.mustRole(role);
    const chain = this.opts.forceProvider
      ? [this.opts.forceProvider, ...rt.profile.fallback_chain]
      : [rt.profile.provider, ...rt.profile.fallback_chain];
    const seen = new Set<string>();
    const ordered = chain.filter((p) => (seen.has(p) ? false : (seen.add(p), true)));
    let lastError: unknown = null;
    let parentLineageIds: string[] = [];
    const modelVersion = (provider: string) => provider === rt.profile.provider ? rt.profile.model_version : "fallback:" + provider;
    const recordAttempt = async (provider: string, modelId: string, startedAt: string, status: "success" | "degraded" | "rejected" | "failed", result?: T, reason?: string, fallbackTo?: string, causationId?: string | null) => {
      const saved = await this.opts.bus?.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: parentLineageIds,
        causation_id: causationId ?? null,
        stage: "mg1." + call,
        operation_version: "mg1." + call + ".router.v1",
        status,
        started_at: startedAt,
        input_refs: inputRefs,
        output_refs: result ? [{ kind: call + "Result", id: traceId, sha256: sha256Json(result) }] : [],
        execution: {
          provider,
          model_id: modelId,
          model_version: modelVersion(provider),
          config_sha256: sha256Json({ role, provider, model_id: modelId, model_version: modelVersion(provider), fallback_chain: rt.profile.fallback_chain, capability_flags: rt.profile.capability_flags, timeout_ms: rt.profile.timeout_ms }),
          ...(result ? {
            latency_ms: result.latency_ms,
            cached: result.cached,
            ...(result.usage ? { input_tokens: result.usage.prompt_tokens, output_tokens: result.usage.completion_tokens } : {}),
          } : {}),
        },
        ...(reason || fallbackTo ? { decision: { ...(reason ? { reason } : {}), ...(fallbackTo ? { fallback_to: fallbackTo } : {}) } } : {}),
        ...(status === "failed" ? { error: "provider attempt failed; detail omitted" } : {}),
      });
      if (saved) parentLineageIds = [saved.lineage_id];
    };
    for (let i = 0; i < ordered.length; i += 1) {
      const providerName = ordered[i]!;
      const isPrimary = i === 0;
      const br = this.breakerFor(role, providerName);
      const modelId = providerName === rt.profile.provider ? rt.profile.model_id : providerName + "-fallback";
      // C-05 数据隔离闸门：private 数据禁止流向 cloud provider。硬拒（非 warning），
      // 不降级改投云端，只逐级尝试 local/cache；全链无 local provider 时显式失败。
      if (requestedDomain === "private") {
        const boundary = this.cfg.providers[providerName]?.trust_boundary;
        if (boundary === "cloud") {
          await degrade({
            layer: "L3",
            trigger: "data_domain=private 遇到 trust_boundary=cloud provider: " + providerName,
            degradedOf: "isolation:private->cloud",
            traceId,
            label: "数据隔离闸门：私有数据不得送云端模型，已拒绝该通道",
            recoveryHint: "改用 trust_boundary=local 的 provider，或把数据域改为 public",
            emit: async (event) => { await this.emitFallback(event); },
          });
          await this.opts.bus?.recordLineage({
            trace_id: traceId,
            parent_lineage_ids: parentLineageIds,
            stage: "mg1.isolation_gate",
            operation_version: "isolation." + call + ".v1",
            status: "rejected",
            input_refs: inputRefs,
            execution: { provider: providerName, model_id: modelId, config_sha256: sha256Json({ role, call, provider: providerName, requested_domain: requestedDomain, boundary }) },
            decision: { reason: "private data must not reach cloud provider", fallback_to: ordered[i + 1] ?? "cache" },
            error: "isolation gate rejected cloud channel for private data",
          });
          continue;
        }
      }
      const startedAt = nowIso();
      if (!br.allow()) {
        lastError = new Error("provider " + providerName + " 熔断中");
        await recordAttempt(providerName, modelId, startedAt, "rejected", undefined, "circuit breaker open", ordered[i + 1] ?? "cache");
        continue;
      }
      let result: T;
      try {
        result = await fn(providerName, modelId);
      } catch (err) {
        br.onFailure();
        lastError = err;
        await recordAttempt(providerName, modelId, startedAt, "failed", undefined, "provider request failed", ordered[i + 1] ?? "cache");
        continue;
      }
      br.onSuccess();
      let finalResult = result;
      let fallbackEventId: string | null = null;
      if (!isPrimary) {
        const d = await degrade({
          layer: "L3",
          trigger: "首选 provider 不可用，切换至 " + providerName,
          degradedOf: providerName,
          traceId,
          label: "模型服务降级通道：" + providerName,
          emit: async (event) => { fallbackEventId = await this.emitFallback(event); },
        });
        finalResult = { ...result, degraded_to: d.degraded_to };
      }
      await recordAttempt(providerName, modelId, startedAt, finalResult.degraded_to ? "degraded" : "success", finalResult, finalResult.degraded_to ? "fallback provider used" : undefined, finalResult.degraded_to || undefined, fallbackEventId);
      await this.record(role, call, providerName, modelId, finalResult, traceId);
      return finalResult;
    }

    const modelId = rt.profile.model_id;
    const cacheStarted = nowIso();
    let result: T;
    try {
      result = await fn("cache", modelId);
    } catch {
      await recordAttempt("cache", modelId, cacheStarted, "failed", undefined, "cache fallback failed");
      throw new Error("模型降级链与 cache fallback 均失败");
    }
    let cacheFallbackEventId: string | null = null;
    const d = await degrade({
      layer: "L3",
      trigger: "fallback_chain 全链失败",
      degradedOf: "cache",
      traceId,
      label: "模型服务全链降级为缓存通道（答案可能陈旧）",
      recoveryHint: "检查 provider 配置与网络；恢复后熔断自动关闭",
      emit: async (event) => { cacheFallbackEventId = await this.emitFallback(event); },
    });
    const finalResult = { ...result, degraded_to: d.degraded_to };
    await recordAttempt("cache", modelId, cacheStarted, "degraded", finalResult, "fallback_chain exhausted", "cache", cacheFallbackEventId);
    await this.record(role, call, "cache", modelId, finalResult, traceId);
    return finalResult;
  }

  private async emitFallback(event: FallbackEvent): Promise<string | null> {
    const envelope = await this.opts.bus?.publish("fallback.events", event, { trace_id: event.trace_id });
    await this.opts.onFallback?.(event);
    return envelope?.event_id ?? null;
  }

  private async record(role: RoleName, call: "chat" | "embed" | "rerank", provider: string, modelId: string, result: MeteredResult, traceId: string): Promise<void> {
    await this.usage.record({
      ts: new Date().toISOString(),
      role,
      provider,
      model_id: modelId,
      call,
      prompt_tokens: result.usage?.prompt_tokens ?? 0,
      completion_tokens: result.usage?.completion_tokens ?? 0,
      latency_ms: result.latency_ms,
      cached: result.cached,
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
