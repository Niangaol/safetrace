import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, sha256Json, SqliteEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { runIngestOnce } from "../src/ingest/src/pipeline.js";
import { runEnrichment } from "../src/enrich/src/index.js";
import { buildSourceEvidenceChunks } from "../src/ingest/src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../src/qa/src/q2-retrieval.js";
import { indexSourceChunks } from "../src/qa/src/source-index.js";
import { ModelGateway, createCliCloudConfirm } from "@safetrace/gateway";

async function readTraceFallbacks(store: SqliteEventStore, traceId: string): Promise<FallbackEvent[]> {
  const found: FallbackEvent[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<FallbackEvent>("fallback.events", offset, 500);
    found.push(...page.filter((event) => event.trace_id === traceId).map((event) => event.payload));
    if (page.length < 500) return found;
  }
}

async function readExistingEnrichmentIds(store: SqliteEventStore): Promise<Set<string>> {
  const ids = new Set<string>();
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<{ intel_id: string }>("enrich.items", offset, 500);
    for (const event of page) ids.add(event.payload.intel_id);
    if (page.length < 500) return ids;
  }
}

async function main(): Promise<void> {
  const traceId = nextId("tr");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_INGEST_OFFLINE !== "false";
  const previousOfflineFixtures = process.env.OFFLINE_FIXTURES;
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    process.env.OFFLINE_FIXTURES = offline ? "true" : "false";
    const ingest = await runIngestOnce({ store, offline, trace_id: traceId });
    const acceptedIds = new Set(ingest.verdicts.filter((v) => v.verdict === "pass" || v.verdict === "degrade").map((v) => v.item_id));
    const accepted = ingest.merged.filter((item) => acceptedIds.has(item.intel_id));
    const alreadyEnriched = await readExistingEnrichmentIds(store);
    const pendingAccepted = accepted.filter((item) => !alreadyEnriched.has(item.intel_id));
    const configuredLimit = process.env.SAFETRACE_ENRICH_LIMIT;
    const enrichLimit = configuredLimit === undefined ? (offline ? pendingAccepted.length : 50) : Number(configuredLimit);
    if (!Number.isInteger(enrichLimit) || enrichLimit < 0 || enrichLimit > 500) throw new Error("SAFETRACE_ENRICH_LIMIT 必须为 0–500 的整数");
    const enrichBatch = pendingAccepted.slice(0, enrichLimit);
    const enrichPending = pendingAccepted.length - enrichBatch.length;
    const enriched = await runEnrichment(enrichBatch, {
      offline,
      bus,
      traceId,
      lineage_parent_by_intel_id: ingest.lineage_parent_by_intel_id,
      causation_by_intel_id: ingest.causation_by_intel_id,
    });
    const runFallbacks = await readTraceFallbacks(store, traceId);
    const enrichmentFallbacks = runFallbacks.filter((event) => /arxiv|epss/i.test(event.trigger));
    const runStatus = ingest.degraded_to || enrichmentFallbacks.length > 0 || enrichPending > 0 ? "degraded" : "success";
    const runFallbackTo = ingest.degraded_to ?? (enrichmentFallbacks.some((event) => event.degraded_of === "fixture") ? "fixture" : (enrichPending > 0 ? "partial_enrichment" : undefined));
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
      status: runStatus,
      input_refs: ingest.merged.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
      output_refs: enriched.map((item) => ({ kind: "EnrichmentResult", id: item.intel_id, sha256: sha256Json(item) })),
      ...(runStatus === "degraded" ? { decision: { fallback_to: runFallbackTo ?? "partial_enrichment", reason: [ingest.degraded_to ? "ingest source degraded to " + ingest.degraded_to : "", enrichmentFallbacks.length ? enrichmentFallbacks.length + " enrichment fallback event(s)" : "", enrichPending ? enrichPending + " accepted item(s) left pending for resumable batches" : ""].filter(Boolean).join("; ") } } : {}),
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
      enrich_limit: enrichLimit,
      enrich_pending: enrichPending,
      enrichment_fallback_events: enrichmentFallbacks.length,
      run_status: runStatus,
      source_chunks: evidence.chunks.length,
      chunks_skipped: evidence.skipped,
      index_mode: vectorIndex.status === "indexed" ? "qdrant_source_index" : "transient_bm25_preview",
      vector_index: vectorIndex,
      degraded_to: runFallbackTo ?? null,
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
    if (previousOfflineFixtures === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = previousOfflineFixtures;
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
