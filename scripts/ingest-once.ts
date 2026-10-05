import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, sha256Json, SqliteEventStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { runIngestOnce } from "../src/ingest/src/pipeline.js";
import { runEnrichment } from "../src/enrich/src/index.js";
import { buildSourceEvidenceChunks } from "../src/ingest/src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../src/qa/src/q2-retrieval.js";
import { indexSourceChunks } from "../src/qa/src/source-index.js";
import { ModelGateway } from "@safetrace/gateway";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { fileURLToPath } from "node:url";
import { planPendingEnrichment } from "../src/enrich/src/pending.js";
import { releasedIntelPayload } from "../src/ingest/src/intel-payload.js";
import { readKnowledgeProjection } from "../src/qa/src/knowledge-reader.js";

async function readTraceFallbacks(store: SqliteEventStore, traceId: string): Promise<FallbackEvent[]> {
  const found: FallbackEvent[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<FallbackEvent>("fallback.events", offset, 500);
    found.push(...page.filter((event) => event.trace_id === traceId).map((event) => event.payload));
    if (page.length < 500) return found;
  }
}


async function main(): Promise<void> {
  const traceId = nextId("tr");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_INGEST_OFFLINE !== "false";
  const previousOfflineFixtures = process.env.OFFLINE_FIXTURES;
  const apply = process.argv.includes("--apply");
  if (apply && process.argv.includes("--dry-run")) throw new Error("--apply and --dry-run are mutually exclusive");
  if (!apply) {
    const snapshot = readIntelIndexSnapshot(dbPath);
    const state = new SqliteEnrichmentStateStore(dbPath, { readOnly: true });
    try {
      const plan = planPendingEnrichment([...snapshot.accepted.values()].map(entry => entry.item), [...snapshot.accepted.values()].map(entry => entry.verdict), [], { states: state.list() });
      console.log(JSON.stringify({ mode: "readonly-ingest-plan", existing_accepted: snapshot.accepted.size, existing_rejected: snapshot.rejected.size, pending_enrichment: plan.pending.length, writes: 0, source_requests: 0, model_calls: 0 }));
    } finally { state.close(); }
    return;
  }
  await requireVerifiedBackup(dbPath);
  const releaseLease = acquireIntelIndexLease("http://127.0.0.1", "enrichment-db:" + dbPath, fileURLToPath(new URL("../.tmp/data-maintenance-locks/", import.meta.url)));
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  const stateStore = new SqliteEnrichmentStateStore(dbPath);
  try {
    process.env.OFFLINE_FIXTURES = offline ? "true" : "false";
    const ingest = await runIngestOnce({ store, offline, trace_id: traceId });
    const acceptedIds = new Set(ingest.verdicts.filter((v) => v.verdict === "pass" || v.verdict === "degrade").map((v) => v.item_id));
    const accepted = ingest.merged.filter((item) => acceptedIds.has(item.intel_id));
    const released = accepted.map(releasedIntelPayload);
    const currentReceipts = [];
    for (let offset = 0; ; offset += 500) { const page = await bus.readEvents<import("@safetrace/shared").EnrichmentResult>("enrich.items", offset, 500); currentReceipts.push(...page); if (page.length < 500) break; }
    const plan = planPendingEnrichment(released, ingest.verdicts, currentReceipts.map(receipt => receipt.payload), { states: stateStore.list(), publishedEnrichments: currentReceipts, currentIntelEventIds: new Map(Object.entries(ingest.causation_by_intel_id)) });
    const pendingAccepted = plan.pending;
    const configuredLimit = process.env.SAFETRACE_ENRICH_LIMIT;
    const enrichLimit = configuredLimit === undefined ? (offline ? pendingAccepted.length : 50) : Number(configuredLimit);
    if (!Number.isInteger(enrichLimit) || enrichLimit < 0 || enrichLimit > 500) throw new Error("SAFETRACE_ENRICH_LIMIT 必须为 0–500 的整数");
    const enrichBatch = pendingAccepted.slice(0, enrichLimit);
    const enrichPending = pendingAccepted.length - enrichBatch.length;
    const enriched = await runEnrichment(enrichBatch, {
      offline,
      bus, stateStore,
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
    const knowledge = !offline && !ingest.degraded_to ? await readKnowledgeProjection({ sqlitePath: dbPath, payloadRoots: [process.env.SAFETRACE_CACHE_DIR ?? resolve("tmp/ingest-cache")] }) : undefined;
    const indexChunksForRun = knowledge?.chunks ?? evidence.chunks;
    const index = new MemoryIndex({ bus });
    await indexChunks(index, indexChunksForRun, {
      collection_name: "ingest_source_preview", model_id: index.modelId, dim: 256, metric: "cosine",
    }, { trace_id: traceId, parent_lineage_ids: evidence.parent_lineage_ids });
    let vectorIndex: { status: "disabled" | "indexed"; chunks: number } = { status: "disabled", chunks: 0 };
    if (process.env.SAFETRACE_INDEX_QDRANT === "true") {
      if (!knowledge || !knowledge.chunks.length) throw new Error("live verified knowledge projection required before vector publishing");
      // Build a separate immutable snapshot collection: an append-only upsert into the old collection would retain revoked chunks.
      const snapshotCollection = "safetrace_knowledge_" + knowledge.fingerprint.slice(0, 16);
      const localFetch: typeof fetch = async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (!["127.0.0.1", "[::1]"].includes(url.hostname)) throw new Error("knowledge embedding only permits literal loopback");
        return fetch(input, { ...init, redirect: "error" });
      };
      const gateway = new ModelGateway({ bus, configPath: "config/models.local.yml", fetchImpl: localFetch });
      vectorIndex = await indexSourceChunks(knowledge.chunks, {
        enabled: true, offline, source_degraded_to: ingest.degraded_to,
        url: process.env.QDRANT_URL ?? "http://127.0.0.1:6333", collection: snapshotCollection, fetch_impl: localFetch,
        api_key: process.env.QDRANT_API_KEY, profile: gateway.embeddingProfile(),
        embedder: (texts, trace) => gateway.embed("embedder", texts, trace),
        bus, trace_id: traceId, parent_lineage_ids: [...new Set(knowledge.evidence.flatMap(record => record.parent_lineage_ids))],
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
      verified_knowledge_chunks: knowledge?.chunks.length ?? 0,
      artifact_chunks: knowledge?.evidence.filter(record => record.kind !== "source").length ?? 0,
      knowledge_projection_rejections: knowledge?.rejected.length ?? 0,
      new_collection_requires_manual_cutover: vectorIndex.status === "indexed",
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
    stateStore.close(); store.close(); releaseLease();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
