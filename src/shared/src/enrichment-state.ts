import { DatabaseSync } from "node:sqlite";
import { sha256Json } from "./lineage.js";
import type { IntelItem } from "./types.js";

export type EnrichmentDimension = "paper" | "cvss" | "epss";
export type EnrichmentStatus = "live" | "degraded" | "empty" | "failed" | "unknown";
export interface EnrichmentDimensionState {
  intel_id: string; dimension: EnrichmentDimension; status: EnrichmentStatus;
  input_hash: string; result_hash: string; enrich_event_id: string | null;
  retry_after: string | null; reason: string; attempts: number; updated_at: string;
  artifact: unknown;
  dependency_hash?: string;
  intel_event_id?: string | null;
  source_receipt?: { url: string; sha256: string; payload: unknown; as_of_date?: string; received_at: string; cve_id: string };
  provenance?: { query_url: string; sha256: string; text: string; paper_records: Record<string,{title:string;summary:string;published_at:string;url:string}> };
  last_good?: Pick<EnrichmentDimensionState, "input_hash" | "result_hash" | "enrich_event_id" | "updated_at" | "artifact">;
}
export interface EnrichmentStateStore {
  get(intelId: string, dimension: EnrichmentDimension): EnrichmentDimensionState | undefined;
  list(intelId?: string): EnrichmentDimensionState[];
  put(record: EnrichmentDimensionState): void;
  atomic?(operation: () => void): void;
  close(): void;
}
/** Receipt timestamps are not changes to the source facts. */
export function enrichmentInputHash(item: IntelItem): string {
  const keys: readonly (keyof IntelItem)[] = ["intel_id", "cve_ids", "ghsa_ids", "osv_ids", "aliases", "source_ids", "title", "summary", "published_at", "entities", "raw_refs", "source_reliability", "schema_version"];
  const facts = Object.fromEntries(keys.filter(key => item[key] !== undefined).map(key => [key, item[key]]));
  return sha256Json({ revision: "enrichment-facts.v2", facts });
}
export function enrichmentRetryDue(state: EnrichmentDimensionState | undefined, inputHash: string, now = new Date()): boolean {
  if (!state || state.input_hash !== inputHash) return true;
  if (state.status === "live") {
    const refreshed = Date.parse(state.updated_at);
    return !Number.isFinite(refreshed) || refreshed > now.getTime() + 5 * 60_000 || refreshed + 24 * 3600_000 <= now.getTime();
  }
  return state.retry_after === null || !Number.isFinite(Date.parse(state.retry_after)) || Date.parse(state.retry_after) <= now.getTime();
}
export function enrichmentRetryAfter(status: EnrichmentStatus, attempts: number, now = new Date()): string | null {
  if (status === "live") return null;
  const base = status === "empty" ? 24 * 3600_000 : 5 * 60_000;
  return new Date(now.getTime() + Math.min(7 * 24 * 3600_000, base * 2 ** Math.min(10, Math.max(0, attempts - 1)))).toISOString();
}
/** Private durable sidecar; no event topic or public contract changes. */
export class SqliteEnrichmentStateStore implements EnrichmentStateStore {
  private db: DatabaseSync;
  private readOnly: boolean;
  private exists: boolean;
  private batching = false;
  constructor(path: string, options: { readOnly?: boolean } = {}) {
    this.readOnly = options.readOnly ?? false;
    this.db = new DatabaseSync(path, { readOnly: this.readOnly });
    if (!this.readOnly) this.db.exec(
      "CREATE TABLE IF NOT EXISTS enrichment_dimension_state (intel_id TEXT NOT NULL, dimension TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(intel_id, dimension));" +
      "CREATE TABLE IF NOT EXISTS enrichment_dimension_history (seq INTEGER PRIMARY KEY AUTOINCREMENT, intel_id TEXT NOT NULL, dimension TEXT NOT NULL, payload TEXT NOT NULL);"
    );
    this.exists = Boolean(this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='enrichment_dimension_state'").get());
  }
  get(intelId: string, dimension: EnrichmentDimension): EnrichmentDimensionState | undefined {
    if (!this.exists) return undefined;
    const row = this.db.prepare("SELECT payload FROM enrichment_dimension_state WHERE intel_id=? AND dimension=?").get(intelId, dimension) as { payload: string } | undefined;
    return row ? JSON.parse(row.payload) as EnrichmentDimensionState : undefined;
  }
  list(intelId?: string): EnrichmentDimensionState[] {
    if (!this.exists) return [];
    const rows = (intelId === undefined ? this.db.prepare("SELECT payload FROM enrichment_dimension_state ORDER BY intel_id,dimension").all() : this.db.prepare("SELECT payload FROM enrichment_dimension_state WHERE intel_id=? ORDER BY dimension").all(intelId)) as { payload: string }[];
    return rows.map(row => JSON.parse(row.payload) as EnrichmentDimensionState);
  }
  put(record: EnrichmentDimensionState): void {
    if (this.readOnly) throw new Error("enrichment state store is read-only");
    if (!record.intel_id || !["paper", "cvss", "epss"].includes(record.dimension) || !["live", "degraded", "empty", "failed", "unknown"].includes(record.status)
      || !/^[a-f0-9]{64}$/.test(record.input_hash) || record.result_hash !== sha256Json(record.artifact)
      || !Number.isSafeInteger(record.attempts) || record.attempts < 1 || !Number.isFinite(Date.parse(record.updated_at))
      || (record.retry_after !== null && !Number.isFinite(Date.parse(record.retry_after)))) throw new Error("invalid enrichment dimension state");
    const previous = this.get(record.intel_id, record.dimension);
    if (previous && Date.parse(record.updated_at) < Date.parse(previous.updated_at)) throw new Error("stale enrichment state cannot overwrite newer state");
    if (previous && record.status !== "live") {
      const good = previous.status === "live" ? { input_hash: previous.input_hash, result_hash: previous.result_hash, enrich_event_id: previous.enrich_event_id, updated_at: previous.updated_at, artifact: previous.artifact } : previous.last_good;
      if (good) record = { ...record, last_good: good };
    }
    if (!this.batching) this.db.exec("BEGIN IMMEDIATE");
    try {
      const payload = JSON.stringify(record);
      this.db.prepare("INSERT INTO enrichment_dimension_history(intel_id,dimension,payload) VALUES(?,?,?)").run(record.intel_id, record.dimension, payload);
      this.db.prepare("INSERT INTO enrichment_dimension_state VALUES(?,?,?) ON CONFLICT(intel_id,dimension) DO UPDATE SET payload=excluded.payload").run(record.intel_id, record.dimension, payload);
      if (!this.batching) this.db.exec("COMMIT");
    } catch (error) { if (!this.batching) this.db.exec("ROLLBACK"); throw error; }
  }
  atomic(operation: () => void): void {
    if (this.readOnly || this.batching) throw new Error("invalid/read-only enrichment state transaction");
    this.db.exec("BEGIN IMMEDIATE"); this.batching = true;
    try { operation(); this.db.exec("COMMIT"); } catch (error) { this.db.exec("ROLLBACK"); throw error; } finally { this.batching = false; }
  }
  close(): void { this.db.close(); }
}
