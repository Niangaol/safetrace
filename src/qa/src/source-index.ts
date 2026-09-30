import { sha256Json } from "@safetrace/shared";
import type { EventBus, EvidenceChunk } from "@safetrace/shared";
import { QdrantEngine, indexChunks } from "./q2-retrieval.js";
import type { EmbeddingFunction } from "./q2-retrieval.js";

export interface SourceIndexOptions {
  enabled: boolean;
  offline: boolean;
  source_degraded_to?: string;
  url?: string;
  collection: string;
  api_key?: string;
  profile: { provider: string; model_id: string; model_version: string; dimension?: number };
  embedder: EmbeddingFunction;
  bus: EventBus;
  trace_id: string;
  parent_lineage_ids: string[];
  fetch_impl?: typeof fetch;
}

/** Production source indexing is opt-in and refuses all fixture/fallback ingest runs. */
export async function indexSourceChunks(chunks: EvidenceChunk[], opts: SourceIndexOptions): Promise<{ status: "disabled" | "indexed"; chunks: number }> {
  const refs = chunks.map(c => ({ kind: "EvidenceChunk", id: c.chunk_id, sha256: sha256Json(c), url: c.provenance.url }));
  if (!opts.enabled) return { status: "disabled", chunks: 0 };
  const p = opts.profile;
  let reason: string | undefined;
  if (opts.offline || process.env.OFFLINE_FIXTURES === "true" || opts.source_degraded_to) reason = "offline or fallback sources cannot enter production vector collection";
  else if (!opts.url || !opts.collection.trim()) reason = "explicit Qdrant URL and collection required";
  else if (p.provider === "cache" || /hash-256|cache/i.test(p.model_id)) reason = "real embedding provider required; cache/hash vectors rejected";
  else if (!p.model_id || !p.model_version || !Number.isInteger(p.dimension) || (p.dimension ?? 0) <= 0) reason = "model identity/version and positive dimension required";
  else if (!opts.parent_lineage_ids.length) reason = "source construction lineage parent required";
  else if (chunks.some(c => !c.provenance.url || !/^[a-f0-9]{64}$/.test(c.provenance.sha256 ?? ""))) reason = "source URL and SHA-256 required for every chunk";
  if (reason) {
    await opts.bus.recordLineage({
      trace_id: opts.trace_id, parent_lineage_ids: opts.parent_lineage_ids,
      stage: "runner.source_index_gate", operation_version: "source-index.v1", status: "rejected",
      input_refs: refs, decision: { reason },
    });
    throw new Error(reason);
  }
  const gate = await opts.bus.recordLineage({
    trace_id: opts.trace_id, parent_lineage_ids: opts.parent_lineage_ids,
    stage: "runner.source_index_gate", operation_version: "source-index.v1", status: "success",
    input_refs: refs, execution: { provider: p.provider, model_id: p.model_id, model_version: p.model_version, vector_dimension: p.dimension },
  });
  const engine = new QdrantEngine({
    url: opts.url, collection: opts.collection, api_key: opts.api_key,
    model_id: p.model_id, model_version: p.model_version, embedding_dim: p.dimension,
    embedder: opts.embedder, bus: opts.bus, fetch_impl: opts.fetch_impl,
  });
  await indexChunks(engine, chunks, {
    collection_name: opts.collection, model_id: p.model_id, model_version: p.model_version,
    dim: p.dimension!, metric: "cosine",
  }, { trace_id: opts.trace_id, parent_lineage_ids: [gate.lineage_id] });
  return { status: "indexed", chunks: chunks.length };
}
