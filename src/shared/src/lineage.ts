import { createHash } from "node:crypto";
import { nextId, nowIso } from "./time.js";
import type { EventStore, LineageDraft, LineageRecord } from "./store.js";

/** Canonical JSON hash: object key order does not affect the artifact digest. */
export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("lineage hash rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((key) => obj[key] !== undefined).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonicalJson(obj[key])).join(",") + "}";
  }
  throw new Error("lineage hash accepts only JSON-compatible values");
}

export function sha256Json(value: unknown): string {
  return sha256(canonicalJson(value));
}

/** Persist an append-only processing record; payloads contain references/hashes, not source text. */
export async function recordLineage(store: EventStore, draft: LineageDraft): Promise<LineageRecord> {
  const completedAt = draft.completed_at ?? nowIso();
  const record: LineageRecord = {
    lineage_id: nextId("ln"),
    trace_id: draft.trace_id,
    parent_lineage_ids: draft.parent_lineage_ids ?? [],
    causation_id: draft.causation_id ?? null,
    stage: draft.stage,
    operation_version: draft.operation_version,
    status: draft.status,
    started_at: draft.started_at ?? completedAt,
    completed_at: completedAt,
    recorded_at: nowIso(),
    input_refs: draft.input_refs ?? [],
    output_refs: draft.output_refs ?? [],
    ...(draft.source ? { source: draft.source } : {}),
    ...(draft.execution ? { execution: draft.execution } : {}),
    ...(draft.decision ? { decision: draft.decision } : {}),
    ...(draft.error ? { error: draft.error } : {}),
  };
  await store.appendLineage(record);
  return record;
}
