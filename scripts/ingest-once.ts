import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, sha256Json, SqliteEventStore } from "@safetrace/shared";
import { runIngestOnce } from "../src/ingest/src/pipeline.js";
import { runEnrichment } from "../src/enrich/src/index.js";
import { buildSourceEvidenceChunks } from "../src/ingest/src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../src/qa/src/q2-retrieval.js";
import { indexSourceChunks } from "../src/qa/src/source-index.js";
import { ModelGateway, createCliCloudConfirm } from "@safetrace/gateway";

async function main(): Promise<void> {
  const traceId = nextId("tr");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_INGEST_OFFLINE !== "false";
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    const ingest = await runIngestOnce({ store, offline, trace_id: traceId });
    const acceptedIds = new Set(ingest.verdicts.filter((v) => v.verdict === "pass" || v.verdict === "degrade").map((v) => v.item_id));
    const accepted = ingest.merged.filter((item) => acceptedIds.has(item.intel_id));
    const enriched = await runEnrichment(accepted, {
      offline,
      bus,
      traceId,
      lineage_parent_by_intel_id: ingest.lineage_parent_by_intel_id,
      causation_by_intel_id: ingest.causation_by_intel_id,
    });
    const evidence = await buildSourceEvidenceChunks(
      ingest.parsed, ingest.fetched, ingest.merged, ingest.verdicts,
      ingest.lineage_parent_by_intel_id, { bus, trace_id: traceId },
    );
    const index = new MemoryIndex({ bus });
    await indexChunks(index, evidence.chunks, {
      collection_name: "ingest_source_preview", model_id: index.modelId, dim: 256, metric: "cosine",
    }, { trace_id: traceId, parent_lineage_ids: evidence.parent_lineage_ids });
    let vectorIndex: { status: "disabled" | "indexed"; chunks: number } = { status: "disabled", chunks: 0 };
    if (process.env.SAFETRACE_INDEX_QDRANT === "true") {
      // 人工关卡：降级到云端前必须人工点头（SAFETRACE_CLOUD_FALLBACK 默认 never=拒绝，不出网不花钱）
      const gateway = new ModelGateway({ bus, confirmCloudFallback: createCliCloudConfirm() });
      vectorIndex = await indexSourceChunks(evidence.chunks, {
        enabled: true, offline, source_degraded_to: ingest.degraded_to,
        url: process.env.QDRANT_URL, collection: process.env.QDRANT_COLLECTION ?? "safetrace_sources",
        api_key: process.env.QDRANT_API_KEY, profile: gateway.embeddingProfile(),
        embedder: (texts, trace) => gateway.embed("embedder", texts, trace),
        bus, trace_id: traceId, parent_lineage_ids: evidence.parent_lineage_ids,
      });
    }
    const prior = await bus.readLineage(traceId);
    const parents = prior.filter((record) => record.stage === "ingest.dq1" || record.stage === "enrich.f6").map((record) => record.lineage_id);
    await bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: parents,
      stage: "runner.ingest_enrich",
      operation_version: "ingest-once-cli.v1",
      status: ingest.degraded_to ? "degraded" : "success",
      input_refs: ingest.merged.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
      output_refs: enriched.map((item) => ({ kind: "EnrichmentResult", id: item.intel_id, sha256: sha256Json(item) })),
      ...(ingest.degraded_to ? { decision: { fallback_to: ingest.degraded_to, reason: "offline or source fallback occurred" } } : {}),
    });
    const lineage = await bus.readLineage(traceId);
    console.log(JSON.stringify({
      trace_id: traceId,
      offline,
      fetched: ingest.fetched.length,
      parsed: ingest.parsed.length,
      merged: ingest.merged.length,
      accepted: accepted.length,
      enriched: enriched.length,
      source_chunks: evidence.chunks.length,
      chunks_skipped: evidence.skipped,
      index_mode: vectorIndex.status === "indexed" ? "qdrant_source_index" : "transient_bm25_preview",
      vector_index: vectorIndex,
      degraded_to: ingest.degraded_to ?? null,
      lineage_records: lineage.length,
      sqlite_path: dbPath,
    }, null, 2));
  } catch {
    await bus.recordLineage({
      trace_id: traceId,
      stage: "runner.ingest_enrich",
      operation_version: "ingest-once-cli.v1",
      status: "failed",
      input_refs: [],
      error: "ingest or enrichment runner failed; details omitted from lineage",
    });
    throw new Error("ingest:once failed; trace_id=" + traceId + " (inspect SQLite lineage)");
  } finally {
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
