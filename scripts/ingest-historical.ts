/**
 * 历史回补（Y1+Y3+Y4+Y6）：抓一段**较早的 pubDate 窗口**并完整走通
 * 采集 → DQ1 → 富化 → 证据块 → 知识投影 → 预览索引 → lineage。
 *
 * 与 scripts/ingest-once.ts 的区别只有窗口：这里跳过 lastMod（近期已入库的几千条不重抓），
 * 只按 pubStartDate/pubEndDate 抓历史条目。其余闸门、备份、lease、降级口径完全一致。
 *
 * 用法：
 *   node --import tsx scripts/ingest-historical.ts --start=2021-12-01T00:00:00.000Z --end=2021-12-15T00:00:00.000Z [--apply] [--limit=600]
 *   不带 --apply 时只做只读计划预览，不写库。
 */
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, sha256Json, SqliteEventStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { runIngestOnce } from "../src/ingest/src/pipeline.js";
import { runEnrichment } from "../src/enrich/src/index.js";
import { buildSourceEvidenceChunks } from "../src/ingest/src/evidence-chunks.js";
import { MemoryIndex, indexChunks } from "../src/qa/src/q2-retrieval.js";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { releasedIntelPayload } from "../src/ingest/src/intel-payload.js";
import { planPendingEnrichment } from "../src/enrich/src/pending.js";
import { readKnowledgeProjection } from "../src/qa/src/knowledge-reader.js";

async function readTraceFallbacks(store: SqliteEventStore, traceId: string): Promise<FallbackEvent[]> {
  const found: FallbackEvent[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<FallbackEvent>("fallback.events", offset, 500);
    found.push(...page.filter((event) => event.trace_id === traceId).map((event) => event.payload));
    if (page.length < 500) return found;
  }
}

function arg(name: string, fallback: string): string {
  const found = process.argv.find((value) => value.startsWith("--" + name + "="));
  return found ? found.slice(name.length + 3) : fallback;
}

async function main(): Promise<void> {
  const start = arg("start", "2021-12-01T00:00:00.000Z");
  const end = arg("end", "2021-12-15T00:00:00.000Z");
  const limitArg = Number(arg("limit", "600"));
  if (!Number.isInteger(limitArg) || limitArg < 1 || limitArg > 2000) throw new Error("--limit 必须为 1–2000 的整数");
  if (!(Date.parse(start) > 0) || !(Date.parse(end) > Date.parse(start))) throw new Error("--start/--end 必须是合法且 start < end 的 ISO 时间");
  const apply = process.argv.includes("--apply");
  if (apply && process.argv.includes("--dry-run")) throw new Error("--apply 与 --dry-run 不可同时使用");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_INGEST_OFFLINE === "true" || process.env.OFFLINE_FIXTURES === "true";
  const traceId = nextId("tr");
  const payloadRoots = [process.env.SAFETRACE_CACHE_DIR ?? resolve("tmp/ingest-cache")];

  if (!apply) {
    const snapshot = readIntelIndexSnapshot(dbPath);
    const state = new SqliteEnrichmentStateStore(dbPath, { readOnly: true });
    try {
      const plan = planPendingEnrichment([...snapshot.accepted.values()].map((e) => e.item), [...snapshot.accepted.values()].map((e) => e.verdict), [], { states: state.list() });
      console.log(JSON.stringify({ dry_run: true, mode: "readonly-historical-plan", window: { start, end }, limit: limitArg, existing_accepted: snapshot.accepted.size, pending: plan.pending.length, real_live_dimensions: plan.real_live_dimensions, writes: 0 }, null, 2));
    } finally { state.close(); }
    return;
  }

  await requireVerifiedBackup(dbPath, process.env.SAFETRACE_VERIFIED_BACKUP_DIR ?? dirname(dbPath) + "/verified-backups");
  const releaseLease = acquireIntelIndexLease("http://127.0.0.1:6333", "safetrace_intel_demo", resolve("tmp/data-maintenance-locks"));
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  const contextStore = new SqliteEnrichmentStateStore(dbPath);
  try {
    const ingest = await runIngestOnce({
      store,
      offline,
      sourceIds: ["nvd_cve"],
      trace_id: traceId,
      limit: limitArg,
      sourceOptions: { nvd_cve: { skipLastModWindow: true, skipPubWindow: false, pubWindow: { start, end } } },
    });

    const snapshot = readIntelIndexSnapshot(dbPath);
    const accepted = [...snapshot.accepted.values()].map((entry) => entry.item).filter((item) => ingest.causation_by_intel_id[item.intel_id] !== undefined);
    const stateStore = contextStore;
    const plan = planPendingEnrichment(
      [...snapshot.accepted.values()].map((entry) => entry.item),
      [...snapshot.accepted.values()].map((entry) => entry.verdict),
      [],
      { states: stateStore.list() },
    );
    const enrichBatch = plan.pending.filter((item) => ingest.causation_by_intel_id[item.intel_id] !== undefined).slice(0, limitArg);
    const enrichPending = plan.pending.length - enrichBatch.length;
    const enriched = enrichBatch.length ? await runEnrichment(enrichBatch, {
      offline,
      bus,
      stateStore,
      traceId,
      lineage_parent_by_intel_id: ingest.lineage_parent_by_intel_id,
      causation_by_intel_id: ingest.causation_by_intel_id,
    }) : [];

    const runFallbacks = await readTraceFallbacks(store, traceId);
    const enrichmentFallbacks = runFallbacks.filter((event) => /arxiv|epss/i.test(event.trigger));
    const runStatus = ingest.degraded_to || enrichmentFallbacks.length > 0 || enrichPending > 0 ? "degraded" : "success";
    const runFallbackTo = ingest.degraded_to ?? (enrichmentFallbacks.some((event) => event.degraded_of === "fixture") ? "fixture" : (enrichPending > 0 ? "partial_enrichment" : undefined));

    const evidence = await buildSourceEvidenceChunks(ingest.parsed, ingest.fetched, ingest.merged, ingest.verdicts, ingest.lineage_parent_by_intel_id, { bus, trace_id: traceId });
    const knowledge = !offline && !ingest.degraded_to ? await readKnowledgeProjection({ sqlitePath: dbPath, payloadRoots }) : undefined;
    const chunksForRun = knowledge?.chunks ?? evidence.chunks;
    const index = new MemoryIndex({ bus });
    await indexChunks(index, chunksForRun, { collection_name: "ingest_historical_preview", model_id: index.modelId, dim: 256, metric: "cosine" }, { trace_id: traceId, parent_lineage_ids: evidence.parent_lineage_ids });

    const prior = await bus.readLineage(traceId);
    const parents = prior.filter((record) => ["ingest.dq1", "enrich.f6"].includes(record.stage)).map((record) => record.lineage_id);
    await bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: parents,
      stage: "runner.historical_backfill",
      operation_version: "ingest-historical-cli.v1",
      status: runStatus,
      input_refs: ingest.merged.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
      output_refs: enriched.map((item) => ({ kind: "EnrichmentResult", id: item.intel_id, sha256: sha256Json(item) })),
      ...(runStatus === "degraded" ? { decision: { fallback_to: runFallbackTo ?? "partial_enrichment", reason: [ingest.degraded_to ? "ingest source degraded to " + ingest.degraded_to : "", enrichmentFallbacks.length ? enrichmentFallbacks.length + " enrichment fallback event(s)" : "", enrichPending ? enrichPending + " accepted item(s) left pending for resumable batches" : ""].filter(Boolean).join("; ") } } : {}),
    });

    const lineage = await bus.readLineage(traceId);
    console.log(JSON.stringify({
      trace_id: traceId,
      window: { start, end, mode: offline ? "fixture/offline" : "nvd_pubDate_backfill" },
      fetched: ingest.fetched.length,
      parsed: ingest.parsed.length,
      merged: ingest.merged.length,
      accepted_this_run: accepted.length,
      dq_verdicts: ingest.verdicts.length,
      dq_breakdown: ingest.verdicts.reduce<Record<string, number>>((acc, verdict) => { const key = String(verdict.verdict ?? "unknown"); acc[key] = (acc[key] ?? 0) + 1; return acc; }, {}),
      publishable_items: accepted.filter((item) => Object.keys(releasedIntelPayload(item)).length > 0).length,
      enriched: enriched.length,
      enrichment_dimensions: enriched.reduce<Record<string, number>>((acc, result) => { for (const dimension of result.dimensions_completed) acc[dimension] = (acc[dimension] ?? 0) + 1; return acc; }, {}),
      enrich_pending_after: enrichPending,
      enrichment_fallback_events: enrichmentFallbacks.length,
      source_chunks: evidence.chunks.length,
      verified_knowledge_chunks: knowledge?.chunks.length ?? 0,
      artifact_chunks: knowledge?.evidence.filter((record) => record.kind !== "source").length ?? 0,
      knowledge_projection_rejections: knowledge?.rejected.length ?? 0,
      chunks_skipped: evidence.skipped,
      index_mode: "transient_bm25_preview",
      degraded_to: runFallbackTo ?? null,
      lineage_records: lineage.length,
      sqlite_path: dbPath,
    }, null, 2));
  } finally {
    contextStore.close();
    store.close();
    releaseLease();
  }
}

void main().catch((error) => { console.error(error); process.exitCode = 1; });
