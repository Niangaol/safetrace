#!/usr/bin/env node
/**
 * Sync latest released SQLite intel into a dedicated Qdrant collection.
 * Default is read-only dry-run; writes and revocations require --apply, after backup verification.
 * --retry IDs uses the SAME latest-event/DQ gate; it never grants permission to an old version.
 * Stop ingestion while applying. A changed snapshot fails closed and cleans the attempted batch.
 * This is a derived summary index, NOT original-source or enrichment-artifact reconstruction.
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { EventBus, SqliteEventStore, MemoryEventStore, nextId, sha256Json } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { readIntelPoints, revokeIntelPoints, cleanupIntelRun, syncIntelIndex } from "../src/qa/src/intel-index-sync.js";
import { indexSourceChunks } from "../src/qa/src/source-index.js";

function integer(name: string, fallback: number, min: number): number {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < min || raw?.trim() === "") throw new Error(name + " must be a safe integer >= " + min);
  return value;
}
function args(values: string[]) {
  let apply = false, dryRun = false; let retryIds: string[] | undefined;
  for (let i = 0; i < values.length; i++) {
    const arg = values[i];
    if (arg === "--apply") apply = true;
    else if (arg === "--dry-run") dryRun = true;
    else if (arg === "--retry") {
      if (retryIds) throw new Error("duplicate --retry");
      retryIds = [];
      while (i + 1 < values.length && !values[i + 1]!.startsWith("--")) retryIds.push(values[++i]!);
      if (!retryIds.length || retryIds.some(id => !/^intel_[0-9A-Za-z_-]+$/.test(id))) throw new Error("--retry requires valid intel IDs");
    } else throw new Error("unknown argument: " + String(arg));
  }
  if (apply && dryRun) throw new Error("--apply and --dry-run are mutually exclusive");
  return { apply, ...(retryIds ? { retryIds } : {}) };
}
/** Indexing never sends embeddings to cloud, even if the active config accidentally selects it. */
const localFetch: typeof fetch = async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (!["127.0.0.1", "[::1]", "::1"].includes(url.hostname) || !["http:", "https:"].includes(url.protocol)) throw new Error("intel index only permits literal loopback endpoints");
  return fetch(input, { ...init, redirect: "error" });
};
async function main(): Promise<void> {
  const cli = args(process.argv.slice(2));
  const batchSize = integer("INTEL_BATCH", 40, 1), limit = integer("INTEL_LIMIT", 0, 0), maxChars = integer("INTEL_MAX_CHARS", 1200, 1);
  const dbPath = process.env.SQLITE_PATH ?? "./var/safetrace.sqlite";
  if (cli.apply) await requireVerifiedBackup(dbPath);
  const collection = process.env.QDRANT_INTEL_COLLECTION ?? "safetrace_intel_demo";
  const qdrant = { url: process.env.QDRANT_URL ?? "http://127.0.0.1:6333", collection,
    apiKey: process.env.QDRANT_API_KEY, fetchImpl: localFetch };
  const releaseLease = cli.apply ? acquireIntelIndexLease(qdrant.url, collection,
    fileURLToPath(new URL("../.tmp/intel-index-locks/", import.meta.url))) : undefined;
  try {
    const snapshot = readIntelIndexSnapshot(dbPath);
    // Constructor resolves a model profile only; no embedding occurs until apply/write.
    const gatewayConfig = process.env.MODELS_CONFIG_PATH ?? "config/models.local.yml";
    const previewGateway = new ModelGateway({ configPath: gatewayConfig, fetchImpl: localFetch });
    const profile = previewGateway.embeddingProfile();
    if (profile.provider === "cache" || /cache|hash-256/i.test(profile.model_id) || !profile.dimension) throw new Error("a real local embedding profile is required; select config/models.local.yml");
    const points = await readIntelPoints(qdrant);
    // Every attempted operation has durable audit storage separate from the read-only business database.
    const auditPath = process.env.INTEL_INDEX_AUDIT_PATH ?? "./var/intel-index-audit.sqlite";
    if (resolve(auditPath) === resolve(dbPath)) throw new Error("index audit database must be separate from business SQLite");
    let auditStore: SqliteEventStore | undefined;
    if (cli.apply) { mkdirSync(dirname(auditPath), { recursive: true }); auditStore = new SqliteEventStore(auditPath); }
    const bus = new EventBus({ store: auditStore ?? new MemoryEventStore() });
    const trace = nextId("tr");
    const gateway = new ModelGateway({ configPath: gatewayConfig, bus, fetchImpl: localFetch });
    try {
      const result = await syncIntelIndex({ ...cli, snapshot, points, model: profile, batchSize, limit, maxChars,
        readSnapshot: () => readIntelIndexSnapshot(dbPath),
        revoke: ids => revokeIntelPoints(ids, qdrant),
        cleanup: ids => cleanupIntelRun(ids, trace, qdrant),
        audit: async (stage, status, data) => { await bus.recordLineage({ trace_id: trace, parent_lineage_ids: [],
          stage: "runner.intel_sync." + stage, operation_version: "intel-sync.v2", status,
          input_refs: [{ kind: "IntelSyncOperation", id: stage, sha256: sha256Json(data) }],
          decision: { reason: JSON.stringify(data) } }); },
        write: async (chunks, markPutAttempted) => {
          const parents = [];
          for (const chunk of chunks) {
            const entry = snapshot.accepted.get(chunk.chunk_id)!;
            const parent = await bus.recordLineage({ trace_id: trace, parent_lineage_ids: [],
              stage: "runner.intel_latest_gate", operation_version: "intel-sync.v2", status: "success",
              input_refs: [{ kind: "EventEnvelope", id: entry.intel_event.event_id, sha256: sha256Json(entry.item) },
                { kind: "QualityVerdict", id: entry.verdict_event.event_id, sha256: sha256Json(entry.verdict) }],
              output_refs: [{ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk) }],
              decision: { reason: "latest ordered DQ bound to current intel; derived summary not raw evidence" } });
            parents.push(parent.lineage_id);
          }
          await indexSourceChunks(chunks, { enabled: true, offline: false, url: qdrant.url, collection,
            api_key: qdrant.apiKey, fetch_impl: localFetch, before_vector_write: markPutAttempted, write_token: trace, profile, bus, trace_id: trace,
            parent_lineage_ids: parents, embedder: (texts, tid) => gateway.embed("embedder", texts, tid) });
        },
      });
      console.log(JSON.stringify({ mode: result.dry_run ? "dry-run" : "applied", trace_id: trace,
        snapshot_seq: snapshot.watermark, accepted: snapshot.accepted.size, rejected: snapshot.rejected.size,
        existing_points: points.length, planned_upserts: result.plan.upsert.length, planned_revokes: result.plan.revoke.length,
        unchanged: result.plan.unchanged, blocked_retry_ids: result.plan.blocked_retry_ids,
        written: result.written, revoked: result.revoked, model_id: profile.model_id, model_version: profile.model_version,
        note: "summary provenance remains untrusted; raw/enrichment reconstruction pending" }, null, 2));
      if (result.plan.blocked_retry_ids.length) process.exitCode = 1;
    } finally { auditStore?.close(); }
  } finally { releaseLease?.(); }
}
main().catch(error => { console.error("[index] failed: " + (error instanceof Error ? error.message : String(error))); process.exitCode = 1; });
