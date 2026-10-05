import type { EvidenceChunk } from "@safetrace/shared";
import { planIntelSync } from "./intel-index-plan.js";
import type { IndexModel, IndexPoint, IntelSnapshot, IntelSyncPlan } from "./intel-index-plan.js";

export interface IntelQdrantOptions { url: string; collection: string; apiKey?: string; fetchImpl?: typeof fetch; timeoutMs?: number }
function endpoint(opts: IntelQdrantOptions): string {
  const url = new URL(opts.url);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("invalid Qdrant URL");
  if (!opts.collection.trim()) throw new Error("explicit intel collection required");
  return opts.url.replace(/\/$/, "") + "/collections/" + encodeURIComponent(opts.collection);
}
async function request(opts: IntelQdrantOptions, suffix: string, body: unknown): Promise<Response> {
  return (opts.fetchImpl ?? fetch)(endpoint(opts) + suffix, { method: "POST", redirect: "error",
    headers: { "content-type": "application/json", ...(opts.apiKey ? { "api-key": opts.apiKey } : {}) },
    body: JSON.stringify(body), signal: AbortSignal.timeout(opts.timeoutMs ?? 10000) });
}
/** Complete scroll or hard failure. A 404 on page one means collection absent, not a partial scan. */
export async function readIntelPoints(opts: IntelQdrantOptions): Promise<IndexPoint[]> {
  const points: IndexPoint[] = []; const cursors = new Set<string>(); let offset: unknown;
  for (let page = 0; page < 10000; page++) {
    const res = await request(opts, "/points/scroll", { limit: 1000, with_vector: false, with_payload: true, ...(offset !== undefined ? { offset } : {}) });
    if (res.status === 404 && page === 0) return [];
    if (!res.ok) throw new Error("Qdrant scroll failed HTTP " + res.status);
    const data = await res.json() as { result?: { points?: unknown; next_page_offset?: unknown } };
    if (!data.result || !Array.isArray(data.result.points)) throw new Error("invalid Qdrant scroll response");
    for (const p of data.result.points as Array<{ id?: unknown; payload?: unknown }>) {
      if ((typeof p.id !== "string" && (typeof p.id !== "number" || !Number.isSafeInteger(p.id))) || !p.payload || typeof p.payload !== "object" || Array.isArray(p.payload)) throw new Error("invalid Qdrant point");
      points.push({ id: p.id, payload: p.payload as Record<string, unknown> });
    }
    offset = data.result.next_page_offset;
    if (offset === null || offset === undefined) return points;
    const cursor = JSON.stringify(offset);
    if (cursors.has(cursor)) throw new Error("Qdrant scroll cursor loop");
    cursors.add(cursor);
  }
  throw new Error("Qdrant scroll page limit exceeded; refusing partial plan");
}
export async function revokeIntelPoints(ids: readonly (string | number)[], opts: IntelQdrantOptions): Promise<void> {
  if (!ids.length) return;
  const res = await request(opts, "/points/delete?wait=true", { points: [...ids] });
  if (!res.ok) throw new Error("Qdrant revoke failed HTTP " + res.status);
  const data = await res.json() as { result?: { status?: string } };
  if (data.result?.status !== "completed") throw new Error("Qdrant revoke not completed");
}
/** Qdrant applies this filter server-side: stale cleanup cannot erase a newer writer's point. */
export async function cleanupIntelRun(chunkIds: readonly string[], runId: string, opts: IntelQdrantOptions): Promise<void> {
  if (!chunkIds.length) return;
  if (!runId) throw new Error("cleanup requires run ownership token");
  const res = await request(opts, "/points/delete?wait=true", { filter: { must: [
    { key: "index_run_id", match: { value: runId } }, { key: "chunk_id", match: { any: [...chunkIds] } },
  ] } });
  if (!res.ok) throw new Error("Qdrant conditional cleanup failed HTTP " + res.status);
  const data = await res.json() as { result?: { status?: string } };
  if (data.result?.status !== "completed") throw new Error("Qdrant conditional cleanup not completed");
}

export interface IntelSyncOptions {
  snapshot: IntelSnapshot; points: readonly IndexPoint[]; model: IndexModel;
  retryIds?: readonly string[]; limit?: number; maxChars?: number; batchSize?: number; apply?: boolean;
  /** Both operations are explicit adapters; a dry-run invokes neither. */
  write: (chunks: EvidenceChunk[], markPutAttempted: () => void) => Promise<void>;
  revoke: (ids: readonly (number | string)[]) => Promise<void>;
  /** Conditional removal of only this run's attempted PUTs, never another writer's replacement. */
  cleanup: (chunkIds: readonly string[]) => Promise<void>;
  readSnapshot: () => IntelSnapshot;
  audit?: (stage: string, status: "success" | "failed" | "rejected", data: unknown) => Promise<void>;
}
export interface IntelSyncResult { plan: IntelSyncPlan; written: number; revoked: number; dry_run: boolean }
/** Stop on first failure; do not reset a model circuit or report partial success as exit zero. */
export async function syncIntelIndex(opts: IntelSyncOptions): Promise<IntelSyncResult> {
  const size = opts.batchSize ?? 40;
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error("INTEL_BATCH must be a positive safe integer");
  const plan = planIntelSync(opts.snapshot, opts.points, opts.model, opts);
  const assertFresh = (): void => {
    if (opts.readSnapshot().fingerprint !== opts.snapshot.fingerprint) throw new Error("intel/DQ snapshot changed; stop producers and re-plan");
  };
  if (!opts.apply) return { plan, written: 0, revoked: 0, dry_run: true };
  await opts.audit?.("plan", "success", { watermark: opts.snapshot.watermark, fingerprint: opts.snapshot.fingerprint,
    upsert: plan.upsert.map(c => c.chunk_id), revoke: plan.revoke, blocked_retry_ids: plan.blocked_retry_ids });
  let written = 0, revoked = 0;
  const committedIds: string[] = [];
  try {
    assertFresh();
    for (let i = 0; i < plan.revoke.length; i += size) {
      assertFresh();
      const batch = plan.revoke.slice(i, i + size);
      await opts.revoke(batch.map(r => r.point_id)); revoked += batch.length;
      await opts.audit?.("revoke", "success", batch); assertFresh();
    }
    // Safety revocation is not suppressed by an invalid retry request; no rejected retry is ever written.
    if (plan.blocked_retry_ids.length) throw new Error("retry IDs not released: " + plan.blocked_retry_ids.join(", "));
    for (let i = 0; i < plan.upsert.length; i += size) {
      assertFresh();
      const batch = plan.upsert.slice(i, i + size);
      let putAttempted = false;
      await opts.audit?.("upsert_attempt", "success", { chunk_ids: batch.map(c => c.chunk_id), fingerprint: opts.snapshot.fingerprint });
      try {
        await opts.write(batch, () => { putAttempted = true; });
        assertFresh();
      } catch (error) {
        // Embed/gate/audit failures before PUT leave existing valid points untouched.
        // After an attempted PUT its outcome may be partial; fail-closed removal requires the collection lease.
        if (putAttempted) await opts.cleanup(batch.map(c => c.chunk_id));
        throw error;
      }
      written += batch.length;
      committedIds.push(...batch.map(c => c.chunk_id));
      await opts.audit?.("upsert", "success", batch.map(c => c.chunk_id));
    }
    // Duplicate IDs are removed only after a canonical replacement was verified successful.
    for (let i = 0; i < plan.prune.length; i += size) {
      assertFresh();
      const batch = plan.prune.slice(i, i + size);
      await opts.revoke(batch.map(r => r.point_id)); revoked += batch.length;
      await opts.audit?.("prune", "success", batch);
    }
    assertFresh();
    await opts.audit?.("complete", "success", { written, revoked, fingerprint: opts.snapshot.fingerprint });
    return { plan, written, revoked, dry_run: false };
  } catch (error) {
    // A change between batches invalidates the entire run, not only its last batch.
    let stillCurrent = false;
    try { stillCurrent = opts.readSnapshot().fingerprint === opts.snapshot.fingerprint; } catch { /* corrupt/unreadable source also invalidates this run */ }
    if (committedIds.length && !stillCurrent) await opts.cleanup(committedIds);
    await opts.audit?.("sync", "failed", { written, revoked, error: error instanceof Error ? error.message : String(error) });
    throw error;
  }
}
