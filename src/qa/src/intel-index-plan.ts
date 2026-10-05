import { sha256, sha256Json } from "@safetrace/shared";
import type { EvidenceChunk, IntelItem, QualityVerdict } from "@safetrace/shared";
import { qdrantPointId } from "./q2-retrieval.js";

export interface IntelIndexEvent {
  seq: number; event_id: string; trace_id: string; causation_id: string | null;
  topic: "intel.items" | "dq.verdicts" | "raw.docs"; payload: unknown;
}
export interface AcceptedIntel {
  item: IntelItem; verdict: QualityVerdict; intel_event: IntelIndexEvent; verdict_event: IntelIndexEvent; raw_event?: IntelIndexEvent;
}
export interface IntelSnapshot {
  watermark: number; fingerprint: string; accepted: Map<string, AcceptedIntel>; rejected: Map<string, string>;
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid intel index event payload");
  return value as Record<string, unknown>;
}
function id(value: unknown): string {
  if (typeof value !== "string" || !/^intel_[0-9A-Za-z_-]+$/.test(value)) throw new Error("invalid intel identity in index snapshot");
  return value;
}
function strings(value: unknown): boolean { return Array.isArray(value) && value.every(x => typeof x === "string"); }
function unit(value: unknown): boolean { return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1; }
function validVerdict(value: Record<string, unknown>): boolean {
  const scores = value.dimension_scores;
  return value.item_kind === "intel" && unit(value.quality_score) && strings(value.flags)
    && typeof value.gate_version === "string" && value.gate_version.length > 0
    && !!scores && typeof scores === "object" && !Array.isArray(scores)
    && ["structure", "completeness", "consistency", "timeliness", "sourcing"].every(key => unit((scores as Record<string, unknown>)[key]));
}
function validItem(value: Record<string, unknown>): boolean {
  const entities = value.entities as Record<string, unknown> | undefined;
  return typeof value.title === "string" && value.title.trim().length > 0
    && Array.isArray(value.cve_ids) && value.cve_ids.every(x => typeof x === "string" && /^CVE-\d{4}-\d{4,}$/.test(x))
    && Array.isArray(value.source_ids) && value.source_ids.length > 0 && value.source_ids.every(x => typeof x === "string")
    && typeof value.published_at === "string" && Number.isFinite(Date.parse(value.published_at))
    && typeof value.first_seen_at === "string" && Number.isFinite(Date.parse(value.first_seen_at))
    && typeof value.source_reliability === "number" && Number.isFinite(value.source_reliability)
    && value.source_reliability >= 0 && value.source_reliability <= 1
    && Array.isArray(value.raw_refs) && value.raw_refs.every(x => typeof x === "string")
    && !!entities && typeof entities === "object" && !Array.isArray(entities)
    && (entities.product === null || typeof entities.product === "string")
    && (entities.vendor === null || typeof entities.vendor === "string")
    && ["version_range", "cwe", "cpes"].every(key => strings(entities[key]))
    && ["aliases", "osv_ids", "ghsa_ids"].every(key => value[key] === undefined || strings(value[key]))
    && value.schema_version === "1.0"
    && (value.summary === undefined || typeof value.summary === "string");
}
/** Total ordering is SQLite seq, never wall-clock time or SELECT's incidental order. */
export function latestIntelSnapshot(events: readonly IntelIndexEvent[]): IntelSnapshot {
  const intel = new Map<string, IntelIndexEvent>();
  const verdicts = new Map<string, IntelIndexEvent>();
  const seenSeq = new Set<number>();
  const rawEvents = new Map<string, IntelIndexEvent>();
  for (const event of events) {
    if (!Number.isSafeInteger(event.seq) || event.seq <= 0 || seenSeq.has(event.seq)) throw new Error("invalid/duplicate index event sequence");
    seenSeq.add(event.seq);
    const p = object(event.payload);
    if (event.topic === "raw.docs") { rawEvents.set(event.event_id, event); continue; }
    // Enriched/raw DQ has its own namespace; it must not replace the source-intel verdict.
    if (event.topic === "dq.verdicts" && ["enriched", "raw"].includes(String(p.item_kind))) continue;
    if (!["intel.items", "dq.verdicts"].includes(event.topic)) throw new Error("unknown index event topic");
    const key = id(event.topic === "intel.items" ? p.intel_id : p.item_id);
    const target = event.topic === "intel.items" ? intel : verdicts;
    if (!target.has(key) || target.get(key)!.seq < event.seq) target.set(key, event);
  }
  const accepted = new Map<string, AcceptedIntel>();
  const rejected = new Map<string, string>();
  for (const key of new Set([...intel.keys(), ...verdicts.keys()])) {
    const it = intel.get(key), dq = verdicts.get(key);
    const item = it ? object(it.payload) : undefined;
    const verdict = dq ? object(dq.payload) : undefined;
    let reason: string | undefined;
    if (!it || !item) reason = "missing intel";
    else if (!validItem(item)) reason = "invalid latest intel";
    else if (!dq || !verdict) reason = "missing latest DQ";
    else if (!(dq.seq > it.seq && dq.causation_id === it.event_id)
      && !(it.seq > dq.seq && it.causation_id === dq.event_id && it.trace_id === dq.trace_id
        && events.filter(e => e.topic === "intel.items" && e.causation_id === dq.event_id).length === 1)) {
      reason = "DQ is not bound to latest intel event (including one-use page admission)";
    }
    else if (verdict.item_kind !== "intel" || !["pass", "degrade"].includes(String(verdict.verdict))) reason = "latest DQ not released";
    else if (!validVerdict(verdict)) reason = "invalid latest DQ shape";
    if (reason) rejected.set(key, reason);
    else {
      const rawEvent = rawEvents.get(it!.causation_id ?? "") ?? rawEvents.get(dq!.causation_id ?? "");
      accepted.set(key, { item: item as unknown as IntelItem, verdict: verdict as unknown as QualityVerdict, intel_event: it!, verdict_event: dq!,
        ...(rawEvent ? { raw_event: rawEvent } : {}) });
    }
  }
  const ordered = [...events].sort((a, b) => a.seq - b.seq);
  return { watermark: ordered.at(-1)?.seq ?? 0, fingerprint: sha256Json(ordered), accepted, rejected };
}
function sourceUrl(entry: AcceptedIntel): string {
  const item = entry.item;
  const raw = entry.raw_event?.payload as Record<string, unknown> | undefined;
  if (item.intel_id.startsWith("intel_page_") && raw && typeof raw.url === "string"
    && item.source_ids.includes(String(raw.source_id)) && item.raw_refs.includes(String(raw.payload_ref))) {
    const url = new URL(raw.url);
    if (url.protocol !== "https:" || url.username || url.password) throw new Error("page source URL is not public HTTPS");
    return url.href;
  }
  const sid = item.source_ids[0];
  const cve = item.cve_ids[0];
  if (sid === "ubuntu_usn") {
    const notice = item.aliases?.find(x => /^USN-\d+-\d+$/i.test(x));
    if (notice) return "https://ubuntu.com/security/notices/" + encodeURIComponent(notice);
    return "https://ubuntu.com/security/notices";
  }
  if (sid === "nvd_cve" && cve) return "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cve);
  if (sid === "cve_org" && cve) return "https://www.cve.org/CVERecord?id=" + encodeURIComponent(cve);
  if (sid === "osv") {
    const osv = item.osv_ids?.[0] ?? item.ghsa_ids?.[0];
    if (osv) return "https://osv.dev/vulnerability/" + encodeURIComponent(osv);
    return "https://osv.dev";
  }
  if (sid === "cisa_kev") return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
  throw new Error("unknown intel source URL: " + String(sid));
}
/** Derived summaries are untrusted until raw-source reconstruction is implemented; SHA is a summary hash. */
export function intelSummaryChunk(entry: AcceptedIntel, maxChars = 1200): EvidenceChunk {
  if (!Number.isSafeInteger(maxChars) || maxChars <= 0) throw new Error("INTEL_MAX_CHARS must be a positive safe integer");
  const item = entry.item;
  let text = [item.cve_ids.join(" "), item.title, item.summary ?? ""].filter(Boolean).join("\n");
  if (text.length > maxChars) text = text.slice(0, maxChars) + "\n[内容过长已按本地 embedder 上下文上限截断]";
  return { chunk_id: item.intel_id, doc_type: "vuln_advisory", text,
    quality_score: entry.verdict.quality_score, published_at: item.published_at, trust: "untrusted",
    provenance: { url: sourceUrl(entry), section: "derived-intel-summary; raw-hash-unverified; item-sha256=" + sha256Json(item), sha256: sha256(text) } };
}
export interface IndexPoint { id: number | string; payload: Record<string, unknown> }
export interface IndexModel { model_id: string; model_version: string }
export function indexPayloadFingerprint(payload: Record<string, unknown>): string {
  return sha256Json({ doc_type: payload.doc_type ?? null, text: payload.text ?? null,
    quality_score: payload.quality_score ?? null, published_at: payload.published_at ?? null, trust: payload.trust ?? null,
    provenance: payload.provenance ?? null, embedding_model_id: payload.embedding_model_id ?? null,
    embedding_model_version: payload.embedding_model_version ?? null });
}
export function desiredPayload(chunk: EvidenceChunk, model: IndexModel): Record<string, unknown> {
  return { ...chunk, embedding_model_id: model.model_id, embedding_model_version: model.model_version };
}
export interface IntelSyncPlan {
  upsert: EvidenceChunk[]; revoke: Array<{ point_id: number | string; chunk_id: string; reason: string }>;
  prune: Array<{ point_id: number | string; chunk_id: string; reason: string }>;
  unchanged: number; blocked_retry_ids: string[];
}
/** Retry narrows writes, not admission or revocation. Limit is applied after latest-version dedupe. */
export function planIntelSync(snapshot: IntelSnapshot, points: readonly IndexPoint[], model: IndexModel,
  opts: { retryIds?: readonly string[]; limit?: number; maxChars?: number } = {}): IntelSyncPlan {
  const limit = opts.limit ?? 0;
  if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("INTEL_LIMIT must be a non-negative safe integer");
  const desired = new Map([...snapshot.accepted].sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, intelSummaryChunk(entry, opts.maxChars)]));
  const owned = new Map<string, IndexPoint[]>();
  for (const point of points) {
    const cid = point.payload.chunk_id;
    if (desired.has(String(cid)) && (point.payload.embedding_model_id !== model.model_id || point.payload.embedding_model_version !== model.model_version)) {
      throw new Error("existing embedding model/version differs or is unknown; rebuild a separate collection, do not mix vector spaces");
    }
    if (typeof cid !== "string" || !cid.startsWith("intel_")) throw new Error("foreign/unidentified point in managed intel collection; use a dedicated collection");
    const list = owned.get(cid) ?? []; list.push(point); owned.set(cid, list);
  }
  // Existing numeric IDs are only 31 bits. Detect collisions before a PUT can replace another chunk.
  const numericOwners = new Map<number | string, string>();
  for (const point of points) numericOwners.set(point.id, String(point.payload.chunk_id));
  const desiredIds = new Map<number, string>();
  for (const cid of desired.keys()) {
    const pid = qdrantPointId(cid), other = desiredIds.get(pid), existing = numericOwners.get(pid);
    if ((other && other !== cid) || (existing && existing !== cid)) throw new Error("Qdrant point ID collision; migrate collection identities before syncing");
    desiredIds.set(pid, cid);
  }
  const revoke: IntelSyncPlan["revoke"] = [];
  const duplicates: IntelSyncPlan["prune"] = [];
  for (const [cid, matches] of owned) {
    for (const point of matches) {
      if (!desired.has(cid)) revoke.push({ point_id: point.id, chunk_id: cid, reason: snapshot.rejected.get(cid) ?? "not in latest released snapshot" });
      else if (point.id !== qdrantPointId(cid)) duplicates.push({ point_id: point.id, chunk_id: cid, reason: "duplicate/noncanonical point" });
    }
  }
  const retry = opts.retryIds ? new Set(opts.retryIds) : undefined;
  const blocked = retry ? [...retry].filter(cid => !desired.has(cid)) : [];
  let pending: EvidenceChunk[] = []; let unchanged = 0;
  for (const [cid, chunk] of desired) {
    const current = owned.get(cid)?.find(p => p.id === qdrantPointId(cid));
    const same = current && indexPayloadFingerprint(current.payload) === indexPayloadFingerprint(desiredPayload(chunk, model));
    if (same && !retry?.has(cid)) { unchanged++; continue; }
    if (!retry || retry.has(cid)) pending.push(chunk);
  }
  if (limit > 0) pending = pending.slice(0, limit);
  const replacing = new Set(pending.map(c => c.chunk_id));
  const prune = duplicates.filter(p => {
    const canonical = owned.get(p.chunk_id)?.find(x => x.id === qdrantPointId(p.chunk_id));
    return replacing.has(p.chunk_id) || (canonical && indexPayloadFingerprint(canonical.payload)
      === indexPayloadFingerprint(desiredPayload(desired.get(p.chunk_id)!, model)));
  });
  return { upsert: pending, revoke, prune, unchanged, blocked_retry_ids: blocked };
}
