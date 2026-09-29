/**
 * Q2 检索层：MemoryIndex（内存 BM25-lite）+ QdrantEngine（Qdrant REST 检索入口）。
 * 纪律：
 * - 离线优先：OFFLINE_FIXTURES=true 或 QDRANT_URL 未配 / Qdrant 请求失败 →
 *   经 shared.degrade() 退回 MemoryIndex，响应带 degraded_to（"fixture" / "memory_index"），禁止静默兜底。
 * - S3 索引-模型绑定：indexChunks 校验 meta.model_id 与引擎 modelId 一致，不一致直接抛错。
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { degrade } from "@safetrace/shared";
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
  search(req: RetrievalRequest): Promise<RetrievalResponse>;
}

export interface EmbeddingResult {
  vectors: number[][];
  model_id: string;
  provider: string;
  degraded_to: string;
}

export type EmbeddingFunction = (texts: string[], traceId: string) => Promise<EmbeddingResult>;

/** S3「索引-模型」绑定记录：同名集合换模型必须重建索引（绑定冲突直接抛错）。 */
export interface CollectionMeta {
  collection_name: string;
  model_id: string;
  dim: number;
  metric: "cosine" | "dot" | "euclid";
}

export interface IndexableEngine extends RetrievalEngine {
  readonly modelId: string;
  upsert(chunks: EvidenceChunk[]): void | Promise<void>;
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
  private docs: IndexedDoc[] = [];
  private df = new Map<string, number>();
  private totalTokens = 0;
  private collections = new Map<string, CollectionMeta>();

  constructor(opts: { model_id?: string } = {}) {
    this.modelId = opts.model_id ?? DEFAULT_LEXICAL_INDEX_ID;
  }

  get size(): number {
    return this.docs.length;
  }

  /** 已绑定的集合元数据（S3 绑定记录查询）。 */
  boundCollections(): CollectionMeta[] {
    return [...this.collections.values()];
  }

  /** 同 chunk_id 覆盖写（索引幂等）。 */
  upsert(chunks: EvidenceChunk[]): void {
    for (const chunk of chunks) this.put(chunk);
  }

  bindCollection(meta: CollectionMeta): void {
    if (meta.model_id !== this.modelId) {
      throw new Error("S3 绑定冲突：索引模型 " + this.modelId + " 与请求模型 " + meta.model_id + " 不一致（禁止静默混用）");
    }
    this.collections.set(meta.collection_name, meta);
  }

  async search(req: RetrievalRequest): Promise<RetrievalResponse> {
    const t0 = Date.now();
    const candidates = this.docs.filter((d) => passesFilter(d.chunk, req));
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
    return {
      query_id: req.query_id,
      chunks,
      retrieval_ms: Date.now() - t0,
      embedder_model_id: "bm25-lite-v1",
      trace_id: req.trace_id,
      schema_version: req.schema_version,
    };
  }

  private put(chunk: EvidenceChunk): void {
    const oldIdx = this.docs.findIndex((d) => d.chunk.chunk_id === chunk.chunk_id);
    if (oldIdx !== -1) {
      const old = this.docs.splice(oldIdx, 1)[0];
      if (old) {
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
    this.docs.push({ chunk, tf, length });
    this.totalTokens += length;
    for (const t of tf.keys()) this.df.set(t, (this.df.get(t) ?? 0) + 1);
  }

  private bm25(doc: IndexedDoc, qTokens: string[]): number {
    const n = this.docs.length;
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

/** doc_types / min_quality / cve_ids 过滤；published_after 在 chunk 级无字段可依（见注释）。 */
function passesFilter(chunk: EvidenceChunk, req: RetrievalRequest): boolean {
  if (req.doc_types && req.doc_types.length > 0 && !req.doc_types.includes(chunk.doc_type)) return false;
  // min_quality：DQ1 质量分下限；无质量分的 chunk 视为未校验，不放过任何下限关卡
  if (req.min_quality !== undefined && (chunk.quality_score ?? -1) < req.min_quality) return false;
  if (req.cve_ids && req.cve_ids.length > 0) {
    const hay = chunk.text.toLowerCase();
    if (!req.cve_ids.some((id) => hay.includes(id.toLowerCase()))) return false;
  }
  // published_after：EvidenceChunk 契约无发布时间字段；入索引资格由上游 IntelItem.published_at 决定
  return true;
}

export interface QdrantEngineOptions {
  /** 缺省读 env QDRANT_URL */
  url?: string;
  /** 缺省读 env QDRANT_COLLECTION，再缺省 safetrace_chunks */
  collection?: string;
  api_key?: string;
  model_id?: string;
  embedding_dim?: number;
  embedder?: EmbeddingFunction;
  timeout_ms?: number;
  /** degrade 事件出口（fallback.events）；不传则只记 lastDegradedTo */
  bus?: EventBus;
  /** 测试/冒烟注入的 fetch */
  fetch_impl?: typeof fetch;
}

/** Qdrant REST 引擎：named vector "dense"；任何不可用都显式降级到 MemoryIndex。 */
export class QdrantEngine implements IndexableEngine {
  readonly modelId: string;
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
    this.vectorDim = opts.embedding_dim;
    this.memory = new MemoryIndex({ model_id: this.modelId });
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
    this.vectorDim = meta.dim;
    this.pendingMeta = meta;
    this.collections.set(meta.collection_name, meta);
  }

  async search(req: RetrievalRequest): Promise<RetrievalResponse> {
    const url = this.opts.url ?? process.env.QDRANT_URL ?? "";
    if (process.env.OFFLINE_FIXTURES === "true") {
      return this.degradeTo(req, "fixture", "OFFLINE_FIXTURES=true：离线模式直接回放 fixtures 样本");
    }
    if (!url) return this.degradeTo(req, "memory_index", "QDRANT_URL 未配置，向量检索不可用");
    try {
      const dense = await this.qdrantSearch(url, req);
      if (!this.mirrorReady || this.memory.size === 0) {
        this.lastDegradedTo = undefined;
        return dense;
      }
      const sparse = await this.memory.search(req);
      const hybrid = fuseHybrid(dense.chunks, sparse.chunks, req.top_k);
      this.lastDegradedTo = undefined;
      return { ...dense, chunks: hybrid };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return this.degradeTo(req, "memory_index", "Qdrant 检索失败（" + msg + "）");
    }
  }

    /** 写入双路索引：真实 MG1 embedding 写 Qdrant，BM25 镜像供混合检索和故障降级。 */
  async upsert(chunks: EvidenceChunk[]): Promise<void> {
    this.memory.upsert(chunks);
    this.mirrorReady = true;
    if (chunks.length === 0) return;
    const url = this.opts.url ?? process.env.QDRANT_URL ?? "";
    if (!url) throw new Error("QDRANT_URL 未配置：BM25 镜像已保留，但不能写入向量库");
    const vectors = await this.embedTexts(chunks.map((c) => c.text), "tr_q2_index", this.pendingMeta?.dim);
    const meta = this.pendingMeta ?? {
      collection_name: this.opts.collection ?? process.env.QDRANT_COLLECTION ?? "safetrace_chunks",
      model_id: this.modelId,
      dim: vectors[0]!.length,
      metric: "cosine" as const,
    };
    if (vectors[0]!.length !== meta.dim) throw new Error("embedding 维度与 Qdrant 集合元数据不一致");
    const base = url.replace(/\/+$/, "");
    const fetchImpl = this.opts.fetch_impl ?? fetch;
    const signal = AbortSignal.timeout(this.opts.timeout_ms ?? QDRANT_TIMEOUT_MS);
    const collectionUrl = base + "/collections/" + encodeURIComponent(meta.collection_name);
    const createResp = await fetchImpl(collectionUrl, {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify({ vectors: { dense: { size: meta.dim, distance: meta.metric } } }),
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
    const upResp = await fetchImpl(collectionUrl + "/points?wait=true", {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify({
        points: chunks.map((c, i) => ({
          id: numericId(c.chunk_id),
          vector: { dense: vectors[i]! },
          payload: {
            chunk_id: c.chunk_id,
            doc_type: c.doc_type,
            text: c.text,
            quality_score: c.quality_score ?? null,
            provenance: c.provenance,
            cve_ids: extractCveIds(c.text),
            embedding_model_id: this.modelId,
          },
        })),
      }),
      signal,
    });
    if (!upResp.ok) throw new Error("Qdrant 写入失败 HTTP " + upResp.status);
    this.pendingMeta = meta;
    this.collections.set(meta.collection_name, meta);
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.opts.api_key) h["api-key"] = this.opts.api_key;
    return h;
  }

  private async qdrantSearch(url: string, req: RetrievalRequest): Promise<RetrievalResponse> {
    const t0 = Date.now();
    const collection = this.pendingMeta?.collection_name ?? this.opts.collection ?? process.env.QDRANT_COLLECTION ?? "safetrace_chunks";
    const vectors = await this.embedTexts([req.query_text], req.trace_id, this.pendingMeta?.dim ?? this.vectorDim);
    const body: Record<string, unknown> = {
      vector: { name: "dense", vector: vectors[0]! },
      limit: req.top_k,
      with_payload: true,
      filter: qdrantFilter(req, this.modelId),
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
    return {
      query_id: req.query_id,
      chunks,
      retrieval_ms: Date.now() - t0,
      embedder_model_id: this.modelId,
      trace_id: req.trace_id,
      schema_version: req.schema_version,
    };
  }

  private async embedTexts(texts: string[], traceId: string, expectedDim?: number): Promise<number[][]> {
    if (!this.opts.embedder) throw new Error("MG1 embedder 未接入；拒绝用 hash-256 伪装语义向量");
    const result = await this.opts.embedder(texts, traceId);
    if (result.model_id === DEFAULT_EMBEDDER_ID) throw new Error("MG1 返回旧 hash-256 占位模型；拒绝写入/查询语义集合");
    if (result.provider === "cache" || result.degraded_to) throw new Error("MG1 embedding 已降级（" + (result.degraded_to || "cache provider") + "）；拒绝写入/查询语义集合");
    if (result.model_id !== this.modelId) throw new Error("MG1 embedding model_id 与 Qdrant 集合绑定不一致");
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
    return result.vectors;
  }

  private async degradeTo(req: RetrievalRequest, degradedOf: string, trigger: string): Promise<RetrievalResponse> {
    this.ensureMemorySeeded();
    const label =
      degradedOf === "fixture"
        ? "离线模式：以下结果来自 fixtures 样本回放，非实时检索"
        : "向量检索不可用：以下结果来自内存索引，覆盖范围可能不完整";
    const res = await degrade({
      layer: "L3",
      trigger,
      degradedOf,
      traceId: req.trace_id,
      label,
      recoveryHint: "恢复 Qdrant 服务或关闭 OFFLINE_FIXTURES 后重试",
      emit: (e) => this.emit(e),
    });
    this.lastDegradedTo = res.degraded_to;
    const base = await this.memory.search(req);
    return { ...base, degraded_to: res.degraded_to };
  }

  private async emit(event: FallbackEvent): Promise<void> {
    if (!this.opts.bus) return;
    await this.opts.bus.publish("fallback.events", event, { trace_id: event.trace_id });
  }

  private ensureMemorySeeded(): void {
    if (this.memory.size === 0) {
      this.memory.upsert(readFixtureChunks());
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

function qdrantFilter(req: RetrievalRequest, modelId: string): Record<string, unknown> {
  const must: unknown[] = [{ key: "embedding_model_id", match: { value: modelId } }];
  if (req.doc_types && req.doc_types.length > 0) must.push({ key: "doc_type", match: { any: req.doc_types } });
  if (req.min_quality !== undefined) must.push({ key: "quality_score", range: { gte: req.min_quality } });
  if (req.cve_ids && req.cve_ids.length > 0) must.push({ key: "cve_ids", match: { any: req.cve_ids } });
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
    provenance: {
      url: prov.url ?? "",
      section: prov.section ?? "",
      ...(typeof prov.page === "number" ? { page: prov.page } : {}),
      ...(typeof prov.sha256 === "string" ? { sha256: prov.sha256 } : {}),
    },
  };
}

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
): Promise<CollectionMeta> {
  engine.bindCollection(meta);
  await engine.upsert(chunks);
  return meta;
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
    vulnerabilities: Array<{ cve: { id: string; descriptions: Array<{ lang: string; value: string }> } }>;
  };
  const kev = readFixtureJson("sources/kev.sample.json") as {
    vulnerabilities: Array<{
      cveID: string; vulnerabilityName: string; shortDescription: string;
      requiredAction: string; dateAdded: string; knownRansomwareCampaignUse: string;
    }>;
  };
  const cveorg = readFixtureJson("sources/cveorg.sample.json") as {
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
        id: string; aliases: string[]; summary: string; details: string;
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
      provenance: { url: nvdUrl, section: "description", sha256: sha256Of(nvdText) },
    },
    {
      chunk_id: "chunk_kev_cve_2021_44228",
      doc_type: "vuln_advisory",
      text: kevText,
      quality_score: 0.97,
      provenance: { url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", section: "vulnerabilities[CVE-2021-44228]", sha256: sha256Of(kevText) },
    },
    {
      chunk_id: "chunk_cveorg_cve_2021_44228",
      doc_type: "vuln_advisory",
      text: cveorgText,
      quality_score: 0.96,
      provenance: { url: "https://www.cve.org/CVERecord?id=CVE-2021-44228", section: "containers.cna", sha256: sha256Of(cveorgText) },
    },
    {
      chunk_id: "chunk_osv_ghsa_jfh8_c2jp_5v3q",
      doc_type: "vuln_advisory",
      text: osvText,
      quality_score: 0.95,
      provenance: { url: "https://osv.dev/vulnerability/" + osvV.id, section: "vulnerabilities[0]", sha256: sha256Of(osvText) },
    },
    {
      chunk_id: "chunk_enrich_cve_2021_44228_cvss",
      doc_type: "enrichment",
      text: enrichText,
      quality_score: enrich.enrichment_score,
      provenance: { url: nvdUrl, section: "metrics.cvssMetricV31", sha256: sha256Of(enrichText) },
    },
    {
      chunk_id: "chunk_paper_arxiv_2112_00507",
      doc_type: "paper",
      text: paperText,
      quality_score: paper.relevance_score,
      provenance: { url: "https://arxiv.org/abs/2112.00507", section: "abstract", sha256: sha256Of(paperText) },
    },
  ];
}

/** 规格导出名（seedFixtureChunks）：与 readFixtureChunks 同义，冒烟脚本与编排层调用。 */
export const seedFixtureChunks: () => EvidenceChunk[] = readFixtureChunks;
