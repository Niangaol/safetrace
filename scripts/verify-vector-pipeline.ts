/**
 * 真实向量链路验收（对应 pilot-doctor 里两个恒为 false 的字段）：
 *   embedding_inference_verified    —— 本地 bge-m3 真实推理，维度/有限性/非零逐项断言
 *   vector_persistence_verified     —— chunk 真实写入 Qdrant，再用语义查询召回并断言排序
 *
 * 与 smoke 的区别：smoke 全离线 fixture 回放（可复现但不真实）；本脚本打真实服务。
 * 用法（需先 pwsh scripts/local/up.ps1）：
 *   node --env-file=.env.local --import tsx scripts/verify-vector-pipeline.ts
 *
 * 红线保持：只用 loopback；不探测云端；不把占位向量当真向量。
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventBus, MemoryEventStore, nextId } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";
import { indexSourceChunks } from "../src/qa/src/source-index.js";
import { QdrantEngine } from "../src/qa/src/q2-retrieval.js";
import { loadModelsConfig } from "../src/gateway/src/profiles.js";

const QDRANT_URL = process.env.QDRANT_URL ?? "http://127.0.0.1:6333";
const COLLECTION = process.env.QDRANT_COLLECTION ?? "safetrace_sources";
const cfgPath = process.env.MODELS_CONFIG_PATH ?? "config/models.tokendance.yml";
const embedderRole = loadModelsConfig(cfgPath).roles.embedder;
const dim = Number(embedderRole.capability_flags.dim);
const modelId = embedderRole.model_id;
const modelVersion = embedderRole.model_version;

const traceId = nextId("tr");
const store = new MemoryEventStore();
const bus = new EventBus({ store });
const gateway = new ModelGateway({ bus });

// 3 段合成来源文本：故意让第一条与查询语义最贴近，便于断言排序（不依赖真实抓取）
const sources = [
  { id: "verify-1", url: "https://vendor.example/verify-usn-1", text: "CVE-2021-44228 Log4Shell remote code execution in Apache Log4j 2.x, fixed in 2.17.0" },
  { id: "verify-2", url: "https://vendor.example/verify-usn-2", text: "Ubuntu security notice for Log4j upgrade on 20.04 LTS and 22.04 LTS" },
  { id: "verify-3", url: "https://vendor.example/verify-kev", text: "CISA KEV catalog entry for CVE-2021-44228 with known ransomware campaign usage" },
];
const chunks = sources.map((s) => ({
  chunk_id: "chk_" + s.id,
  doc_type: "vuln_advisory" as const,
  text: s.text,
  provenance: { url: s.url, section: "", sha256: createHash("sha256").update(s.text).digest("hex") },
}));

console.log("[verify] embedding 模型:", modelId, "维度:", dim, "版本:", modelVersion);

// ---- 1. 真实 embedding 推理 ----
const emb = await gateway.embed("embedder", chunks.map((c) => c.text), traceId);
assert.equal(emb.provider !== "cache" && emb.degraded_to === "", true, "embedding 必须来自真实 provider 且未降级");
assert.equal(emb.vectors.length, chunks.length, "向量数量与输入一致");
assert.equal(emb.vectors[0]!.length, dim, "向量维度必须与配置一致，实际 " + emb.vectors[0]!.length);
for (const v of emb.vectors) {
  assert.ok(v.every((x) => Number.isFinite(x)), "向量含非有限值");
  assert.ok(v.some((x) => x !== 0), "向量全零（疑似占位）");
}
console.log("[verify] embedding 推理通过：", emb.vectors.length, "条 /", emb.vectors[0]!.length, "维 / provider", emb.provider);

// ---- 2. 真实写入 Qdrant（走六道闸门的正门） ----
// 记下写入前的点数：清理断言要跟这个基线比，不能假设集合是空的
// （生产集合里本来就有真实数据，写死“删完应 < 写入数”会误报）。
const baselineCount = ((await (await fetch(QDRANT_URL.replace(/\/+$/, "") + "/collections/" + encodeURIComponent(COLLECTION))).json()) as { result?: { points_count?: number } }).result?.points_count ?? 0;
const parentLineage = await bus.recordLineage({
  trace_id: traceId,
  parent_lineage_ids: [],
  causation_id: null,
  stage: "ingest.evidence_chunks",
  operation_version: "verify-vector-pipeline.v1",
  status: "success",
  started_at: new Date().toISOString(),
  input_refs: chunks.map((c) => ({ kind: "EvidenceChunk", id: c.chunk_id, sha256: c.provenance.sha256, url: c.provenance.url })),
  output_refs: chunks.map((c) => ({ kind: "EvidenceChunk", id: c.chunk_id, sha256: c.provenance.sha256, url: c.provenance.url })),
});
const write = await indexSourceChunks(chunks, {
  enabled: true,
  offline: false,
  url: QDRANT_URL,
  collection: COLLECTION,
  profile: { provider: embedderRole.provider, model_id: modelId, model_version: modelVersion, dimension: dim },
  bus,
  trace_id: traceId,
  parent_lineage_ids: [parentLineage.lineage_id],
  embedder: async (texts, tid) => gateway.embed("embedder", texts, tid),
});
assert.deepEqual(write, { status: "indexed", chunks: chunks.length });
console.log("[verify] Qdrant 写入通过：", JSON.stringify(write));

// ---- 3. 语义召回并断言排序 ----
const engine = new QdrantEngine({
  url: QDRANT_URL,
  collection: COLLECTION,
  model_id: modelId,
  model_version: modelVersion,
  embedding_dim: dim,
  bus,
  embedder: async (texts, tid) => gateway.embed("embedder", texts, tid),
});
engine.bindCollection({ collection_name: COLLECTION, model_id: modelId, model_version: modelVersion, dim, metric: "cosine" });
assert.equal(engine.lastDegradedTo, undefined, "检索不得降级（降级即不是真向量链路）");
const res = await engine.search({
  query_id: "q_verify_vector",
  query_text: "Log4Shell remote code execution fix version",
  top_k: 3,
  trace_id: traceId,
  schema_version: "1.0",
});
assert.equal(res.chunks.length, chunks.length, "召回数量与写入数量一致");
assert.equal(res.chunks[0]!.chunk_id, "chk_verify-1", "语义最贴近的 chunk 必须排第一，实际 " + res.chunks[0]!.chunk_id);
const scores = res.chunks.map((c) => c.score_dense ?? 0);
assert.ok(scores[0]! > scores[1]! && scores[1]! > scores[2]!, "分数必须递减，实际 " + JSON.stringify(scores));
for (const c of res.chunks) assert.ok(c.provenance.url !== "" && c.provenance.sha256 !== "", "召回 chunk 必须带完整溯源");
console.log("[verify] 语义召回通过：", res.chunks.map((c) => c.chunk_id + "(" + (c.score_dense ?? 0) + ")").join(" > "));

// ---- 4. 清场：删掉本次验证写入的点，避免污染生产集合 ----
// 点 id 算法必须与 QdrantEngine.numericId 完全一致（sha256 前 4 字节 mod 2147483647），
// 否则删不干净（之前用 sha1 试过，HTTP 200 但点还在）。
const numericId = (s: string): number => createHash("sha256").update(s).digest().readUInt32BE(0) % 2147483647;
const del = await fetch(QDRANT_URL.replace(/\/+$/, "") + "/collections/" + encodeURIComponent(COLLECTION) + "/points/delete?wait=true", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ points: chunks.map((c) => numericId(c.chunk_id)) }),
});
const remaining = ((await (await fetch(QDRANT_URL.replace(/\/+$/, "") + "/collections/" + encodeURIComponent(COLLECTION))).json()) as { result?: { points_count?: number } }).result?.points_count;
assert.equal(remaining, baselineCount, "验证点未清理干净：写入前 " + baselineCount + " 点，删除后 " + remaining + " 点；本次写入 " + chunks.length + " 点应全部删除");
console.log("[verify] 清理验证点后集合剩余", remaining, "点");

console.log("");
console.log("[verify] 真实向量链路验收通过：embedding 推理 + Qdrant 写入 + 语义召回");
