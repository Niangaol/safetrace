/**
 * Q2 检索层：MemoryIndex（内存 BM25-lite）+ QdrantEngine（Qdrant REST 检索入口）。
 * 纪律：
 * - 离线优先：OFFLINE_FIXTURES=true 或 QDRANT_URL 未配 / Qdrant 请求失败 →
 *   经 shared.degrade() 退回 MemoryIndex，响应带 degraded_to（"fixture" / "memory_index"），禁止静默兜底。
 * - S3 索引-模型绑定：indexChunks 校验 meta.model_id 与引擎 modelId 一致，不一致直接抛错。
 * - A-05 时效过滤真实生效：published_after 一旦指定，双引擎（MemoryIndex/Qdrant）都必须按
 *   chunk.published_at 过滤；缺 published_at = 时效未知，按最不新鲜处理（时间窗内一律滤除）。
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { degrade, nextId, nowIso, parseLoose, sha256, sha256Json } from "@safetrace/shared";
import type { EventBus, EvidenceChunk, FallbackEvent, RetrievalRequest, RetrievalResponse } from "@safetrace/shared";

/** 仅兼容旧配置/哈希工具；Qdrant 写入必须使用 MG1 provider 返回的真实 embedding。 */
export const DEFAULT_EMBEDDER_ID = "hash-256";
export const DEFAULT_LEXICAL_INDEX_ID = "bm25-lite-v1";
const K1 = 1.2;
const B = 0.75;
const QDRANT_TIMEOUT_MS = 5000;
const FIXTURE_DIR = "../../../fixtures/"; // 相对 src/qa/src/
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const LATIN_RE = /[a-z0-9][a-z0-9._-]*/g;
const CJK_RE = /[\u4e00-\u9fff]+/g;

export interface RetrievalEngine {
  search(req: RetrievalRequest, context?: IndexLineageContext): Promise<RetrievalResponse>;
}

export interface EmbeddingResult {
  vectors: number[][];
  model_id: string;
  model_version?: string;
  provider: string;
  degraded_to: string;
}

export type EmbeddingFunction = (texts: string[], traceId: string) => Promise<EmbeddingResult>;

/** S3「索引-模型」绑定记录：同名集合换模型必须重建索引（绑定冲突直接抛错）。 */
export interface CollectionMeta {
  collection_name: string;
  model_id: string;
  model_version?: string;
  dim: number;
  metric: "cosine" | "dot" | "euclid";
}

export interface IndexLineageContext { trace_id?: string; parent_lineage_ids?: string[]; causation_id?: string | null }

export interface IndexableEngine extends RetrievalEngine {
  readonly modelId: string;
  upsert(chunks: EvidenceChunk[], context?: IndexLineageContext): void | Promise<void>;
  bindCollection(meta: CollectionMeta): void;
}

/** 分词：拉丁/数字整词 + CJK 单字与相邻二元组（无分词器依赖的轻量近似）。 */
export function tokenize(text: string): string[] {
  const tokens: string[] = [];
  const lower = text.toLowerCase();
  for (const m of lower.matchAll(LATIN_RE)) tokens.push(m[0]);
  for (const run of lower.match(CJK_RE) ?? []) {
    for (const ch of run) tokens.push(ch);
    for (let i = 0; i + 1 < run.length; i += 1) tokens.push(run.slice(i, i + 2));
  }
  return tokens;
}

/** 旧特征哈希辅助函数仅供兼容性测试；不得写入语义 Qdrant 集合。 */
export function hashVector(text: string, dim: number): number[] {
  const v = new Array<number>(dim).fill(0);
  for (const t of tokenize(text)) {
    const h = createHash("sha256").update(t).digest();
    const idx = h.readUInt32BE(0) % dim;
    const sign = (h[4] ?? 0) % 2 === 0 ? 1 : -1;
    v[idx] = (v[idx] ?? 0) + sign;
  }
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1;
  return v.map((x) => x / norm);
}

function queryLineageRefs(req: RetrievalRequest): Array<{ kind: string; id: string; sha256: string }> {
  return [
    { kind: "RetrievalRequest", id: req.query_id, sha256: sha256Json(req) },
    { kind: "QueryText", id: req.query_id, sha256: sha256(req.query_text) },
  ];
}

function round4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

function extractCveIds(text: string): string[] {
  return (text.match(CVE_RE) ?? []).map((s) => s.toUpperCase());
}

interface IndexedDoc {
  chunk: EvidenceChunk;
  tf: Map<string, number>;
  length: number;
}

/** 内存 BM25-lite 索引：词项 TF*IDF + 长度归一；同时充当所有降级路径的兜底索引。 */
export class MemoryIndex implements IndexableEngine {
  readonly modelId: string;
  private docs = new Map<string, IndexedDoc>();
  private df = new Map<string, number>();
  private totalTokens = 0;
  private collections = new Map<string, CollectionMeta>();
  private readonly bus?: EventBus;

  constructor(opts: { model_id?: string; bus?: EventBus } = {}) {
    this.modelId = opts.model_id ?? DEFAULT_LEXICAL_INDEX_ID;
    this.bus = opts.bus;
  }

  get size(): number {
    return this.docs.size;
  }

  /** 已绑定的集合元数据（S3 绑定记录查询）。 */
  boundCollections(): CollectionMeta[] {
    return [...this.collections.values()];
  }

  /** 同 chunk_id 覆盖写（索引幂等）；有 EventBus 时追加记录每批输入/输出 hash。 */
  async upsert(chunks: EvidenceChunk[], context: IndexLineageContext = {}): Promise<void> {
    for (const chunk of chunks) this.put(chunk);
    if (!this.bus) return;
    const traceId = context.trace_id ?? nextId("tr");
    const refs = chunks.map((chunk) => ({ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url }));
    await this.bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: context.parent_lineage_ids ?? [],
      causation_id: context.causation_id ?? null,
      stage: "q2.bm25_index",
      operation_version: "bm25-lite.v1",
      status: "success",
      input_refs: refs,
      output_refs: refs.map((ref) => ({ ...ref, kind: "BM25IndexedChunk" })),
      execution: { component_version: "bm25-lite.v1", model_id: "bm25-lite-v1" },
    });
  }

  bindCollection(meta: CollectionMeta): void {
    if (meta.model_id !== this.modelId) {
      throw new Error("S3 绑定冲突：索引模型 " + this.modelId + " 与请求模型 " + meta.model_id + " 不一致（禁止静默混用）");
    }
    this.collections.set(meta.collection_name, meta);
  }

  async search(req: RetrievalRequest, context: IndexLineageContext = {}): Promise<RetrievalResponse> {
    return (await this.searchWithLineage(req, context)).response;
  }

  async searchWithLineage(req: RetrievalRequest, context: IndexLineageContext = {}): Promise<{ response: RetrievalResponse; lineage_id?: string }> {
    const startedAt = nowIso();
    const t0 = Date.now();
    const afterMs = publishedAfterBound(req.published_after);
    const candidates = [...this.docs.values()].filter(d => passesFilter(d.chunk, req, afterMs));
    const qTokens = [...new Set(tokenize(req.query_text))];
    const scored: Array<{ chunk: EvidenceChunk; score: number }> = [];
    for (const doc of candidates) {
      const score = this.bm25(doc, qTokens);
      if (score > 0) scored.push({ chunk: doc.chunk, score });
    }
    scored.sort((a, b) => b.score - a.score || a.chunk.chunk_id.localeCompare(b.chunk.chunk_id));
    const top = scored.slice(0, Math.max(0, req.top_k));
    const max = top.length > 0 ? top[0]!.score : 0;
    const chunks: EvidenceChunk[] = top.map(({ chunk, score }) => {
      const indexed = { ...chunk };
      delete indexed.score_dense;
      delete indexed.score_rerank;
      return { ...indexed, score_sparse: round4(max > 0 ? score / max : 0) };
    });
    const response: RetrievalResponse = {
      query_id: req.query_id,
      chunks,
      retrieval_ms: Date.now() - t0,
      embedder_model_id: "bm25-lite-v1",
      trace_id: req.trace_id,
      schema_version: req.schema_version,
    };
    const lineage = await this.bus?.recordLineage({
      trace_id: req.trace_id,
      parent_lineage_ids: context.parent_lineage_ids ?? [],
      causation_id: context.causation_id ?? null,
      stage: "q2.bm25_search",
      operation_version: "bm25-lite.v1",
      status: "success",
      started_at: startedAt,
      input_refs: queryLineageRefs(req),
      output_refs: chunks.map((chunk) => ({ kind: "RetrievedChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
      execution: { component_version: "bm25-lite.v1", model_id: "bm25-lite-v1" },
    });
    return { response, ...(lineage ? { lineage_id: lineage.lineage_id } : {}) };
  }

  private put(chunk: EvidenceChunk): void {
    const old = this.docs.get(chunk.chunk_id);
    if (old) {
      this.docs.delete(chunk.chunk_id);
      {
        this.totalTokens -= old.length;
        for (const t of old.tf.keys()) {
          const n = (this.df.get(t) ?? 1) - 1;
          if (n <= 0) this.df.delete(t);
          else this.df.set(t, n);
        }
      }
    }
    const tokens = tokenize(chunk.text);
    const tf = new Map<string, number>();
    for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
    const length = Math.max(1, tokens.length);
    this.docs.set(chunk.chunk_id, { chunk, tf, length });
    this.totalTokens += length;
    for (const t of tf.keys()) this.df.set(t, (this.df.get(t) ?? 0) + 1);
  }

  private bm25(doc: IndexedDoc, qTokens: string[]): number {
    const n = this.docs.size;
    if (n === 0) return 0;
    const avgdl = this.totalTokens / n;
    let score = 0;
    for (const t of qTokens) {
      const tf = doc.tf.get(t);
      if (!tf) continue;
      const df = this.df.get(t) ?? 0;
      if (df === 0) continue;
      const idf = Math.log(1 + (n - df + 0.5) / (df + 0.5));
      const denom = tf + K1 * (1 - B + B * (doc.length / avgdl));
      score += idf * ((tf * (K1 + 1)) / denom);
    }
    return score;
  }
}

/**
 * A-05：published_after 归一为 epoch ms。
 * 不可解析 → 抛错（fail-closed）：静默放过等于让"时效过滤"重新变成假的。
 */
function publishedAfterBound(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const ms = parseLoose(raw);
  if (ms === null) throw new Error("published_after 无法解析为时间戳：" + raw);
  return ms;
}

/** doc_types / min_quality / cve_ids / published_after 过滤（A-05：时效过滤真实生效）。 */
function passesFilter(chunk: EvidenceChunk, req: RetrievalRequest, afterMs?: number): boolean {
  if (req.doc_types && req.doc_types.length > 0 && !req.doc_types.includes(chunk.doc_type)) return false;
  // min_quality：DQ1 质量分下限；无质量分的 chunk 视为未校验，不放过任何下限关卡
  if (req.min_quality !== undefined && (chunk.quality_score ?? -1) < req.min_quality) return false;
  if (req.cve_ids && req.cve_ids.length > 0) {
    const ids = new Set(extractCveIds(chunk.text));
    if (!req.cve_ids.some(id => ids.has(id.toUpperCase()))) return false;
  }
  // published_after（A-05）：EvidenceChunk.published_at 缺省 = 时效未知，按最不新鲜处理；
  // 时间窗一经指定，未知时效一律滤除——不用抓取时间顶替，也不静默放过。
  if (afterMs !== undefined) {
    const published = chunk.published_at === undefined ? null : parseLoose(chunk.published_at);
    if (published === null || published < afterMs) return false;
  }
  return true;
}

export interface QdrantEngineOptions {
  /** 缺省读 env QDRANT_URL */
  url?: string;
  /** 缺省读 env QDRANT_COLLECTION，再缺省 safetrace_chunks */
  collection?: string;
  api_key?: string;
  model_id?: string;
  model_version?: string;
  embedding_dim?: number;
  embedder?: EmbeddingFunction;
  timeout_ms?: number;
  /** degrade 事件出口（fallback.events）；不传则只记 lastDegradedTo */
  bus?: EventBus;
  /** 测试/冒烟注入的 fetch */
  fetch_impl?: typeof fetch;
  /** Called immediately before a points PUT, never for embedding or collection setup failures. */
  before_upsert?: () => void;
  /** Operation owner used for conditional recovery of uncertain PUT outcomes. */
  write_token?: string;
}

/** Qdrant REST 引擎：named vector "dense"；任何不可用都显式降级到 MemoryIndex。 */
export class QdrantEngine implements IndexableEngine {
  readonly modelId: string;
  modelVersion: string | undefined;
  /** 最近一次降级通道（/healthz 透出）；未降级为 undefined */
  lastDegradedTo: string | undefined;
  private readonly opts: QdrantEngineOptions;
  private readonly memory: MemoryIndex;
  private readonly collections = new Map<string, CollectionMeta>();
  private pendingMeta: CollectionMeta | undefined;
  private vectorDim: number | undefined;
  private mirrorReady = false;

  constructor(opts: QdrantEngineOptions = {}) {
    this.opts = opts;
    this.modelId = opts.model_id ?? DEFAULT_EMBEDDER_ID;
    this.modelVersion = opts.model_version;
    this.vectorDim = opts.embedding_dim;
    this.memory = new MemoryIndex({ model_id: this.modelId, bus: opts.bus });
  }

  get size(): number {
    return this.memory.size;
  }

  boundCollections(): CollectionMeta[] {
    return [...this.collections.values()];
  }

  bindCollection(meta: CollectionMeta): void {
    if (meta.model_id !== this.modelId) {
      throw new Error("S3 绑定冲突：索引模型 " + this.modelId + " 与请求模型 " + meta.model_id + " 不一致（禁止静默混用）");
    }
    if (!Number.isInteger(meta.dim) || meta.dim <= 0) throw new Error("S3 集合维度必须是正整数");
    if (this.vectorDim !== undefined && this.vectorDim !== meta.dim) throw new Error("S3 集合维度与 embedder 配置不一致");
    if (this.modelVersion !== undefined && meta.model_version !== undefined && this.modelVersion !== meta.model_version) throw new Error("S3 集合模型版本与 embedder 配置不一致");
    this.modelVersion = meta.model_version ?? this.modelVersion;
    this.vectorDim = meta.dim;
    this.pendingMeta = meta;
    this.collections.set(meta.collection_name, meta);
  }

  async search(req: RetrievalRequest, context: IndexLineageContext = {}): Promise<RetrievalResponse> {
    const url = this.opts.url ?? process.env.QDRANT_URL ?? "";
    if (process.env.OFFLINE_FIXTURES === "true") return this.degradeTo(req, "fixture", "OFFLINE_FIXTURES=true：离线模式直接回放 fixtures 样本", context);
    if (!url) return this.degradeTo(req, "memory_index", "QDRANT_URL 未配置，向量检索不可用", context);
    try {
      const dense = await this.qdrantSearch(url, req, context);
      if (!this.mirrorReady || this.memory.size === 0) {
        this.lastDegradedTo = undefined;
        return dense.response;
      }
      const sparse = await this.memory.searchWithLineage(req);
      const hybrid = fuseHybrid(dense.response.chunks, sparse.response.chunks, req.top_k);
      const refs = hybrid.map((chunk) => ({ kind: "RetrievedChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url }));
      await this.opts.bus?.recordLineage({
        trace_id: req.trace_id,
        parent_lineage_ids: [dense.lineage_id, sparse.lineage_id].filter((id): id is string => Boolean(id)),
        causation_id: context.causation_id ?? null,
        stage: "q2.hybrid_fusion",
        operation_version: "rrf.k60.v1",
        status: "success",
        input_refs: [{ kind: "Query", id: req.query_id, sha256: sha256(req.query_text) }, ...dense.response.chunks.map((chunk) => ({ kind: "DenseCandidate", id: chunk.chunk_id, sha256: sha256Json(chunk) })), ...sparse.response.chunks.map((chunk) => ({ kind: "SparseCandidate", id: chunk.chunk_id, sha256: sha256Json(chunk) }))],
        output_refs: refs,
        execution: { component_version: "rrf.k60.v1", model_id: this.modelId },
      });
      this.lastDegradedTo = undefined;
      return { ...dense.response, chunks: hybrid };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const failed = await this.opts.bus?.recordLineage({
        trace_id: req.trace_id,
        parent_lineage_ids: context.parent_lineage_ids ?? [],
        causation_id: context.causation_id ?? null,
        stage: "q2.qdrant_search",
        operation_version: "qdrant-rest.search.v1",
        status: /cache|hash-256|embedding|model|维度/i.test(msg) ? "rejected" : "failed",
        input_refs: queryLineageRefs(req),
        output_refs: [],
        execution: { component_version: "qdrant-rest.v1", model_id: this.modelId },
        decision: { fallback_to: "bm25-lite", reason: "dense retrieval unavailable" },
        error: "dense retrieval failed validation or transport",
      });
      return this.degradeTo(req, "memory_index", "Qdrant 检索失败（" + msg + "）", context, failed ? [failed.lineage_id] : []);
    }
  }

    /** 写入双路索引：真实 MG1 embedding 写 Qdrant，BM25 镜像供混合检索和故障降级。 */
  async upsert(chunks: EvidenceChunk[], context: IndexLineageContext = {}): Promise<void> {
    const traceId = context.trace_id ?? nextId("tr");
    const startedAt = nowIso();
    const bm25Context = { ...context, trace_id: traceId };
    await this.memory.upsert(chunks, bm25Context);
    this.mirrorReady = true;
    if (chunks.length === 0) return;
    const inputRefs = chunks.map((chunk) => ({ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url }));
    const url = this.opts.url ?? process.env.QDRANT_URL ?? "";
    const fetchImpl = this.opts.fetch_impl ?? fetch;
    const signal = AbortSignal.timeout(this.opts.timeout_ms ?? QDRANT_TIMEOUT_MS);
    let embedding: EmbeddingResult | undefined;
    try {
      if (!url) throw new Error("QDRANT_URL 未配置：BM25 镜像已保留，但不能写入向量库");
      embedding = await this.embedTexts(chunks.map((c) => c.text), traceId, this.pendingMeta?.dim);
      const vectors = embedding.vectors;
      const modelVersion = embedding.model_version ?? this.modelVersion;
      const meta = this.pendingMeta ?? {
        collection_name: this.opts.collection ?? process.env.QDRANT_COLLECTION ?? "safetrace_chunks",
        model_id: this.modelId,
        model_version: embedding.model_version ?? this.modelVersion,
        dim: vectors[0]!.length,
        metric: "cosine" as const,
      };
      if (vectors[0]!.length !== meta.dim) throw new Error("embedding 维度与 Qdrant 集合元数据不一致");
      const base = url.replace(/\/+$/, "");
      const collectionUrl = base + "/collections/" + encodeURIComponent(meta.collection_name);
      const createResp = await fetchImpl(collectionUrl, {
        method: "PUT",
        headers: this.headers(),
        body: JSON.stringify({ vectors: { dense: { size: meta.dim, distance: ({ cosine: "Cosine", dot: "Dot", euclid: "Euclid" } as const)[meta.metric] } } }),
        signal,
      });
      if (!createResp.ok && createResp.status !== 409) throw new Error("Qdrant 建集失败 HTTP " + createResp.status);
      if (createResp.status === 409) {
        const infoResp = await fetchImpl(collectionUrl, { method: "GET", headers: this.headers(), signal });
        if (!infoResp.ok) throw new Error("Qdrant 已有集合但读取元数据失败 HTTP " + infoResp.status);
        const info = (await infoResp.json()) as { result?: { config?: { params?: { vectors?: { dense?: { size?: number; distance?: string } } } } } };
        const existing = info.result?.config?.params?.vectors?.dense;
        if (existing?.size !== meta.dim) throw new Error("Qdrant 已有集合维度不匹配；必须新建集合并重建索引");
        if (existing.distance && existing.distance.toLowerCase() !== meta.metric.toLowerCase()) throw new Error("Qdrant 已有集合距离度量不匹配");
      }
      this.opts.before_upsert?.();
      const upResp = await fetchImpl(collectionUrl + "/points?wait=true", {
        method: "PUT",
        headers: this.headers(),
        body: JSON.stringify({
          points: chunks.map((chunk, index) => ({
            id: numericId(chunk.chunk_id),
            vector: { dense: vectors[index]! },
            payload: {
              chunk_id: chunk.chunk_id,
              ...(this.opts.write_token ? { index_run_id: this.opts.write_token } : {}),
              doc_type: chunk.doc_type,
              text: chunk.text,
              quality_score: chunk.quality_score ?? null,
              ...(chunk.published_at ? { published_at: chunk.published_at } : {}),
              ...(chunk.trust ? { trust: chunk.trust } : {}),
              provenance: chunk.provenance,
              cve_ids: extractCveIds(chunk.text),
              embedding_model_id: this.modelId,
              ...(modelVersion ? { embedding_model_version: modelVersion } : {}),
            },
          })),
        }),
        signal,
      });
      if (!upResp.ok) throw new Error("Qdrant 写入失败 HTTP " + upResp.status);
      const upResult = await upResp.json() as { result?: { status?: string } };
      if (upResult.result?.status !== "completed") throw new Error("Qdrant points PUT did not confirm completed");
      this.pendingMeta = meta;
      this.collections.set(meta.collection_name, meta);
      await this.opts.bus?.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: context.parent_lineage_ids ?? [],
        causation_id: context.causation_id ?? null,
        stage: "q2.qdrant_index",
        operation_version: "qdrant-rest.v1",
        status: "success",
        started_at: startedAt,
        input_refs: inputRefs,
        output_refs: chunks.map((chunk, index) => ({ kind: "QdrantPoint", id: chunk.chunk_id, sha256: sha256Json(vectors[index]!), url: chunk.provenance.url })),
        execution: { component_version: "qdrant-rest.v1", provider: embedding.provider, model_id: embedding.model_id, model_version: embedding.model_version ?? this.modelVersion ?? embedding.model_id, vector_dimension: vectors[0]!.length, config_sha256: sha256Json({ collection_name: meta.collection_name, model_id: meta.model_id, model_version: meta.model_version, dim: meta.dim, metric: meta.metric }) },
        decision: { reason: "collection=" + meta.collection_name + "; dim=" + meta.dim + "; metric=" + meta.metric },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const reason = /cache|hash-256|embedding|model_id|维度/i.test(message) ? "embedding validation failed" : "Qdrant write failed";
      await this.opts.bus?.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: context.parent_lineage_ids ?? [],
        causation_id: context.causation_id ?? null,
        stage: "q2.qdrant_index",
        operation_version: "qdrant-rest.v1",
        status: "degraded",
        started_at: startedAt,
        input_refs: inputRefs,
        output_refs: [],
        execution: { component_version: "qdrant-rest.v1", model_id: this.modelId, ...(embedding ? { provider: embedding.provider } : {}) },
        decision: { fallback_to: "bm25-lite", reason },
        error: reason,
      });
      throw err;
    }
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.opts.api_key) h["api-key"] = this.opts.api_key;
    return h;
  }

  private async qdrantSearch(url: string, req: RetrievalRequest, context: IndexLineageContext = {}): Promise<{ response: RetrievalResponse; lineage_id?: string }> {
    const startedAt = nowIso();
    const t0 = Date.now();
    const collection = this.pendingMeta?.collection_name ?? this.opts.collection ?? process.env.QDRANT_COLLECTION ?? "safetrace_chunks";
    const embedding = await this.embedTexts([req.query_text], req.trace_id, this.pendingMeta?.dim ?? this.vectorDim);
    const vector = embedding.vectors[0]!;
    const body: Record<string, unknown> = {
      vector: { name: "dense", vector },
      limit: req.top_k,
      with_payload: true,
      filter: qdrantFilter(req, this.modelId, this.modelVersion),
    };
    const fetchImpl = this.opts.fetch_impl ?? fetch;
    const resp = await fetchImpl(url.replace(/\/+$/, "") + "/collections/" + encodeURIComponent(collection) + "/points/search", {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.opts.timeout_ms ?? QDRANT_TIMEOUT_MS),
    });
    if (!resp.ok) throw new Error("Qdrant HTTP " + resp.status);
    const data = (await resp.json()) as {
      result?: Array<{ id: string | number; score: number; payload?: Record<string, unknown> }>;
    };
    const chunks = (data.result ?? []).slice(0, req.top_k).map((p) => toChunk(p));
    const response: RetrievalResponse = {
      query_id: req.query_id,
      chunks,
      retrieval_ms: Date.now() - t0,
      embedder_model_id: this.modelId,
      trace_id: req.trace_id,
      schema_version: req.schema_version,
    };
    const lineage = await this.opts.bus?.recordLineage({
      trace_id: req.trace_id,
      parent_lineage_ids: context.parent_lineage_ids ?? [],
      causation_id: context.causation_id ?? null,
      stage: "q2.qdrant_search",
      operation_version: "qdrant-rest.search.v1",
      status: "success",
      started_at: startedAt,
      input_refs: queryLineageRefs(req),
      output_refs: [
        { kind: "QueryEmbedding", id: req.query_id, sha256: sha256Json(vector) },
        ...chunks.map((chunk) => ({ kind: "DenseCandidate", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
      ],
      execution: { component_version: "qdrant-rest.v1", provider: embedding.provider, model_id: embedding.model_id, model_version: embedding.model_version ?? this.modelVersion ?? embedding.model_id, vector_dimension: vector.length, config_sha256: sha256Json({ collection_name: collection, model_id: this.modelId, model_version: this.modelVersion, vector_dimension: vector.length }) },
      decision: { reason: "collection=" + collection },
    });
    return { response, ...(lineage ? { lineage_id: lineage.lineage_id } : {}) };
  }

  private async embedTexts(texts: string[], traceId: string, expectedDim?: number): Promise<EmbeddingResult> {
    if (!this.opts.embedder) throw new Error("MG1 embedder 未接入；拒绝用 hash-256 伪装语义向量");
    const result = await this.opts.embedder(texts, traceId);
    if (result.model_id === DEFAULT_EMBEDDER_ID) throw new Error("MG1 返回旧 hash-256 占位模型；拒绝写入/查询语义集合");
    if (result.provider === "cache" || result.degraded_to) throw new Error("MG1 embedding 已降级（" + (result.degraded_to || "cache provider") + "）；拒绝写入/查询语义集合");
    if (result.model_id !== this.modelId) throw new Error("MG1 embedding model_id 与 Qdrant 集合绑定不一致");
    if (this.modelVersion !== undefined && result.model_version !== this.modelVersion) throw new Error("MG1 embedding model_version 与 Qdrant 集合绑定不一致");
    this.modelVersion = result.model_version ?? this.modelVersion;
    if (!Array.isArray(result.vectors) || result.vectors.length !== texts.length) throw new Error("MG1 embedding 返回数量与输入不一致");
    const dimension = result.vectors[0]?.length ?? 0;
    if (dimension <= 0 || (expectedDim !== undefined && dimension !== expectedDim)) throw new Error("MG1 embedding 向量维度无效或不匹配");
    for (const vector of result.vectors) {
      if (vector.length !== dimension || vector.some((value) => typeof value !== "number" || !Number.isFinite(value))) {
        throw new Error("MG1 embedding 含维度不一致或非有限数值");
      }
    }
    if (this.vectorDim !== undefined && this.vectorDim !== dimension) throw new Error("MG1 embedding 维度与当前集合绑定不一致");
    this.vectorDim = dimension;
    return result;
  }

  private async degradeTo(
    req: RetrievalRequest,
    degradedOf: string,
    trigger: string,
    context: IndexLineageContext = {},
    failedLineageIds: string[] = [],
  ): Promise<RetrievalResponse> {
    await this.ensureMemorySeeded(req.trace_id);
    const label = degradedOf === "fixture"
      ? "离线模式：以下结果来自 fixtures 样本回放，非实时检索"
      : "向量检索不可用：以下结果来自内存索引，覆盖范围可能不完整";
    let fallbackEvent: FallbackEvent | undefined;
    let fallbackEventId: string | undefined;
    const res = await degrade({
      layer: "L3",
      trigger,
      degradedOf,
      traceId: req.trace_id,
      label,
      recoveryHint: "恢复 Qdrant 服务或关闭 OFFLINE_FIXTURES 后重试",
      emit: async (event) => { fallbackEvent = event; fallbackEventId = (await this.emit(event)) ?? undefined; },
    });
    this.lastDegradedTo = res.degraded_to;
    const sparse = await this.memory.searchWithLineage(req, { parent_lineage_ids: failedLineageIds, causation_id: context.causation_id });
    const response = { ...sparse.response, degraded_to: res.degraded_to };
    await this.opts.bus?.recordLineage({
      trace_id: req.trace_id,
      parent_lineage_ids: [...failedLineageIds, ...(sparse.lineage_id ? [sparse.lineage_id] : [])],
      causation_id: fallbackEventId ?? context.causation_id ?? null,
      stage: "q2.retrieval_fallback",
      operation_version: "q2-fallback.v1",
      status: "degraded",
      input_refs: queryLineageRefs(req),
      output_refs: [
        ...response.chunks.map((chunk) => ({ kind: "RetrievedChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
        ...(fallbackEvent && fallbackEventId ? [{ kind: "FallbackEvent", id: fallbackEventId, sha256: sha256Json(fallbackEvent) }] : []),
      ],
      decision: { fallback_to: res.degraded_to, reason: degradedOf === "fixture" ? "explicit offline fixture mode" : "dense store unavailable" },
    });
    return response;
  }


  private async emit(event: FallbackEvent): Promise<string | undefined> {
    if (!this.opts.bus) return undefined;
    const envelope = await this.opts.bus.publish("fallback.events", event, { trace_id: event.trace_id });
    return envelope.event_id;
  }

  private async ensureMemorySeeded(traceId: string): Promise<void> {
    if (this.memory.size === 0) {
      await this.memory.upsert(readFixtureChunks(), { trace_id: traceId });
      this.mirrorReady = false;
    }
  }
}

export function fuseHybrid(denseChunks: EvidenceChunk[], sparseChunks: EvidenceChunk[], topK: number): EvidenceChunk[] {
  const rows = new Map<string, { chunk: EvidenceChunk; denseRank?: number; sparseRank?: number }>();
  denseChunks.forEach((chunk, index) => rows.set(chunk.chunk_id, { chunk, denseRank: index + 1 }));
  sparseChunks.forEach((chunk, index) => {
    const row = rows.get(chunk.chunk_id);
    if (row) {
      row.chunk = { ...row.chunk, score_sparse: chunk.score_sparse };
      row.sparseRank = index + 1;
    } else {
      rows.set(chunk.chunk_id, { chunk, sparseRank: index + 1 });
    }
  });
  return [...rows.values()]
    .map(({ chunk, denseRank, sparseRank }) => {
      const fusedScore = (denseRank === undefined ? 0 : 1 / (60 + denseRank)) + (sparseRank === undefined ? 0 : 1 / (60 + sparseRank));
      const result = { ...chunk };
      delete result.score_rerank;
      return { chunk: result, fusedScore };
    })
    .sort((a, b) => b.fusedScore - a.fusedScore || a.chunk.chunk_id.localeCompare(b.chunk.chunk_id))
    .slice(0, Math.max(0, topK))
    .map((row) => row.chunk);
}

function qdrantFilter(req: RetrievalRequest, modelId: string, modelVersion?: string): Record<string, unknown> {
  const must: unknown[] = [{ key: "embedding_model_id", match: { value: modelId } }];
  if (modelVersion) must.push({ key: "embedding_model_version", match: { value: modelVersion } });
  if (req.doc_types && req.doc_types.length > 0) must.push({ key: "doc_type", match: { any: req.doc_types } });
  if (req.min_quality !== undefined) must.push({ key: "quality_score", range: { gte: req.min_quality } });
  if (req.cve_ids && req.cve_ids.length > 0) must.push({ key: "cve_ids", match: { any: req.cve_ids } });
  // Qdrant 的日期字段须用 datetime_range，numeric range 不支持字符串日期。
  // 缺 published_at 的点不匹配；UTC 归一与内存筛选同口径。
  const after = publishedAfterBound(req.published_after);
  if (after !== undefined) must.push({ key: "published_at", datetime_range: { gte: new Date(after).toISOString() } });
  return { must };
}

function toChunk(p: { id: string | number; score: number; payload?: Record<string, unknown> }): EvidenceChunk {
  const pl = p.payload ?? {};
  const prov = (pl.provenance ?? {}) as { url?: string; section?: string; page?: number; sha256?: string };
  return {
    chunk_id: String(pl.chunk_id ?? p.id),
    doc_type: (pl.doc_type as EvidenceChunk["doc_type"]) ?? "vuln_advisory",
    text: String(pl.text ?? ""),
    score_dense: round4(p.score),
    ...(typeof pl.quality_score === "number" ? { quality_score: pl.quality_score } : {}),
    // Qdrant 载荷里的可选元数据：缺省即"未知"，不补默认值、不猜时间
    ...(typeof pl.published_at === "string" && pl.published_at !== "" ? { published_at: pl.published_at } : {}),
    ...(pl.trust === "trusted" || pl.trust === "untrusted" ? { trust: pl.trust } : {}),
    provenance: {
      url: prov.url ?? "",
      section: prov.section ?? "",
      ...(typeof prov.page === "number" ? { page: prov.page } : {}),
      ...(typeof prov.sha256 === "string" ? { sha256: prov.sha256 } : {}),
    },
  };
}

export { numericId as qdrantPointId };

function numericId(s: string): number {
  return createHash("sha256").update(s).digest().readUInt32BE(0) % 2147483647;
}

/**
 * S3 索引-模型绑定：先校验并登记绑定记录，再写入 chunks；
 * 模型不一致直接抛错（同名集合换模型 = 换索引，禁止静默混用）。
 */
export async function indexChunks(
  engine: IndexableEngine,
  chunks: EvidenceChunk[],
  meta: CollectionMeta,
  context: IndexLineageContext = {},
): Promise<CollectionMeta> {
  engine.bindCollection(meta);
  await engine.upsert(chunks, context);
  return meta;
}

function readFixtureText(rel: string): string {
  return readFileSync(new URL(FIXTURE_DIR + rel, import.meta.url), "utf8");
}

/** 用 shared 的口径把上游日期归一为 ISO-8601 UTC；不可解析返回 undefined（不猜时间）。 */
function isoOrUndefined(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const ms = parseLoose(raw);
  return ms === null ? undefined : new Date(ms).toISOString();
}

function readFixtureJson(rel: string): unknown {
  return JSON.parse(readFileSync(new URL(FIXTURE_DIR + rel, import.meta.url), "utf8"));
}

function must<T>(v: T | undefined | null, what: string): T {
  if (v === undefined || v === null) throw new Error("fixture 缺字段：" + what);
  return v;
}

function sha256Of(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * 从 fixtures/ 构建种子 chunks（冒烟与离线检索用）。
 * 内容全部可回溯到 fixtures/sources/*.sample.json 与 enrichmentresult.sample.json；
 * 中文摘要取自 IntelItem.summary 口径，不添加 fixtures 之外的事实。
 */
export function readFixtureChunks(): EvidenceChunk[] {
  const nvd = readFixtureJson("sources/nvd.sample.json") as {
    vulnerabilities: Array<{ cve: { id: string; published?: string; descriptions: Array<{ lang: string; value: string }> } }>;
  };
  const kev = readFixtureJson("sources/kev.sample.json") as {
    vulnerabilities: Array<{
      cveID: string; vulnerabilityName: string; shortDescription: string;
      requiredAction: string; dateAdded: string; knownRansomwareCampaignUse: string;
    }>;
  };
  const cveorg = readFixtureJson("sources/cveorg.sample.json") as {
    cveMetadata?: { datePublished?: string };
    containers: {
      cna: {
        title: string;
        descriptions: Array<{ value: string }>;
        affected: Array<{ vendor: string; product: string; versions: Array<{ version: string; lessThanOrEqual?: string; status: string }> }>;
      };
    };
  };
  const osv = readFixtureJson("sources/osv.sample.json") as {
    results: Array<{
      vulns: Array<{
        id: string; aliases: string[]; summary: string; details: string; published?: string;
        affected: Array<{ package: { name: string }; ranges: Array<{ events: Array<{ introduced?: string; fixed?: string }> }> }>;
      }>;
    }>;
  };
  const enrich = readFixtureJson("enrichmentresult.sample.json") as {
    enrichment_score: number;
    artifacts: {
      papers: Array<{ paper_id: string; title: string; year?: number; relevance_score: number; evidence_terms?: string[] }>;
      score_assessment: {
        cvss_v3_base: number; cvss_v3_vector: string; epss_score?: number; epss_percentile?: number;
        kev_flag?: boolean; exploit_maturity?: string; impact_summary?: string;
      };
    };
  };

  const nvdCve = must(nvd.vulnerabilities[0], "nvd.vulnerabilities[0]");
  const nvdDesc = must(nvdCve.cve.descriptions.find((d) => d.lang === "en") ?? nvdCve.cve.descriptions[0], "nvd.descriptions.en");
  const kevV = must(kev.vulnerabilities[0], "kev.vulnerabilities[0]");
  const cna = must(cveorg.containers.cna, "cveorg.containers.cna");
  const osvV = must(osv.results[0]?.vulns[0], "osv.results[0].vulns[0]");
  const sa = enrich.artifacts.score_assessment;
  const paper = must(enrich.artifacts.papers[0], "enrich.artifacts.papers[0]");
  const summary = "Apache Log4j2 <=2.14.1 JNDI 特性无法防御攻击者控制的 LDAP 端点，可致远程代码执行。";
  const nvdUrl = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228";

  const nvdText =
    nvdDesc.value +
    " （CVE-2021-44228，别名 Log4Shell）中文摘要：" + summary +
    " 受影响版本 2.0-beta9 至 2.15.0（不含 2.12.2 / 2.12.3 / 2.3.1 安全版本），CVSS v3.1 基础分 10.0。";
  const kevText =
    kevV.vulnerabilityName + "（CVE-2021-44228，Log4Shell）。描述：" + kevV.shortDescription +
    " 处置要求：" + kevV.requiredAction +
    " 已知勒索软件组织利用：" + kevV.knownRansomwareCampaignUse +
    "。列入 CISA KEV 日期 " + kevV.dateAdded + "。";
  const aff0 = must(cna.affected[0], "cveorg.affected[0]");
  const ver0 = must(aff0.versions[0], "cveorg.affected[0].versions[0]");
  const cveorgText =
    cna.title + "（CVE-2021-44228，别名 Log4Shell）。描述：" + must(cna.descriptions[0], "cveorg.descriptions[0]").value +
    " 受影响产品与版本：" + aff0.vendor + " " + aff0.product + " " + (ver0.lessThanOrEqual ?? ver0.version) +
    " 及以下（" + ver0.status + "）。";
  const osvAff = osvV.affected[0];
  const osvIntro = osvAff?.ranges[0]?.events.find((e) => e.introduced)?.introduced ?? "";
  const osvFix = osvAff?.ranges[0]?.events.find((e) => e.fixed)?.fixed ?? "";
  const osvText =
    osvV.summary + "（" + osvV.id + "，别名 " + osvV.aliases.join(" / ") + " / Log4Shell）。详情：" + osvV.details +
    (osvIntro || osvFix
      ? " 影响与修复版本：" + osvIntro + " 引入，" + osvFix + " 修复（" + (osvAff?.package.name ?? "") + "）。"
      : "");
  const enrichText =
    "CVE-2021-44228（Log4Shell）富化结果：CVSS v3.1 基础分 " + sa.cvss_v3_base +
    "（" + sa.cvss_v3_vector + "，来源 NVD）；" +
    (sa.epss_score !== undefined ? "EPSS " + sa.epss_score + "（百分位 " + sa.epss_percentile + "）；" : "") +
    (sa.kev_flag ? "已列入 KEV；" : "") +
    (sa.exploit_maturity ? "利用成熟度 " + sa.exploit_maturity + "。" : "") +
    (sa.impact_summary ? "影响摘要：" + sa.impact_summary : "");
  // arXiv fixture 提供 entry 级 <published>；用于论文 chunk 的上游发布时间
  const arxivXml = readFixtureText("enrich/arxiv.sample.xml");
  const paperPublished = (() => {
    // fixture 的 paper_id 形如 "arXiv:2112.00507"，Atom 里是 abs/2112.00507v1；按编号片段匹配
    const key = paper.paper_id.includes(":") ? paper.paper_id.slice(paper.paper_id.indexOf(":") + 1) : paper.paper_id;
    const entry = arxivXml.split("<entry>").find((block) => block.includes(key));
    return isoOrUndefined(entry?.match(/<published>([^<]+)<\/published>/)?.[1]);
  })();
  const paperText =
    "论文《" + paper.title + "》（" + paper.paper_id + (paper.year ? "，" + paper.year : "") +
    "）：分析 CVE-2021-44228（Log4Shell）漏洞及其利用的学术研究，关联度 " + paper.relevance_score +
    (paper.evidence_terms?.length ? "，证据词 " + paper.evidence_terms.join(" / ") : "") + "。";

  return [
    {
      chunk_id: "chunk_nvd_cve_2021_44228_desc",
      doc_type: "vuln_advisory",
      text: nvdText,
      quality_score: 0.98,
      published_at: isoOrUndefined(nvdCve.cve.published),
      trust: "trusted",
      provenance: { url: nvdUrl, section: "description", sha256: sha256Of(nvdText) },
    },
    {
      chunk_id: "chunk_kev_cve_2021_44228",
      doc_type: "vuln_advisory",
      text: kevText,
      quality_score: 0.97,
      published_at: isoOrUndefined(kevV.dateAdded),
      trust: "trusted",
      provenance: { url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", section: "vulnerabilities[CVE-2021-44228]", sha256: sha256Of(kevText) },
    },
    {
      chunk_id: "chunk_cveorg_cve_2021_44228",
      doc_type: "vuln_advisory",
      text: cveorgText,
      quality_score: 0.96,
      published_at: isoOrUndefined(cveorg.cveMetadata?.datePublished),
      trust: "trusted",
      provenance: { url: "https://www.cve.org/CVERecord?id=CVE-2021-44228", section: "containers.cna", sha256: sha256Of(cveorgText) },
    },
    {
      chunk_id: "chunk_osv_ghsa_jfh8_c2jp_5v3q",
      doc_type: "vuln_advisory",
      text: osvText,
      quality_score: 0.95,
      published_at: isoOrUndefined(osvV.published),
      trust: "trusted",
      provenance: { url: "https://osv.dev/vulnerability/" + osvV.id, section: "vulnerabilities[0]", sha256: sha256Of(osvText) },
    },
    {
      chunk_id: "chunk_enrich_cve_2021_44228_cvss",
      doc_type: "enrichment",
      text: enrichText,
      quality_score: enrich.enrichment_score,
      published_at: isoOrUndefined(nvdCve.cve.published),
      trust: "trusted",
      provenance: { url: nvdUrl, section: "metrics.cvssMetricV31", sha256: sha256Of(enrichText) },
    },
    {
      chunk_id: "chunk_paper_arxiv_2112_00507",
      doc_type: "paper",
      text: paperText,
      quality_score: paper.relevance_score,
      published_at: paperPublished,
      trust: "trusted",
      provenance: { url: "https://arxiv.org/abs/2112.00507", section: "abstract", sha256: sha256Of(paperText) },
    },
  ];
}

/** 规格导出名（seedFixtureChunks）：与 readFixtureChunks 同义，冒烟脚本与编排层调用。 */
export const seedFixtureChunks: () => EvidenceChunk[] = readFixtureChunks;
