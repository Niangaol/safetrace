/** Durable reference-only handoff. All queue operations are synchronous and atomic.
 * Lease recovery is at-least-once: queue transitions are idempotent/token-fenced,
 * arbitrary enrichment/index side effects are NOT exactly-once. isCurrent is only
 * a snapshot: business writes must recheck the version + token in their own atomic
 * commit boundary (or use an equivalent destination CAS). Never check then await
 * an unguarded write; expired/replaced owners must not publish results.
 * intel_event_seq must be the durable monotonic event sequence, not wall time.
 */
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export type UpdateStage = "enrich" | "index";
export interface UpdateDraft {
  intel_id: string;
  refs: string[];
  input_hash: string;
  intel_event_seq: number;
  detected_at: number;
  priority?: number;
  refresh_key?: string;
}
export interface UpdateTask extends UpdateDraft {
  priority: number;
  stage: UpdateStage | "done";
  status: "pending" | "running" | "done" | "blocked" | "revoked";
  revoked_seq: number | null;
  revoked_at: number | null;
  revision: number;
  enqueued_at: number;
  started_at: number | null;
  enriched_at: number | null;
  index_started_at: number | null;
  indexed_at: number | null;
  next_attempt_at: number;
  attempts: number;
  owner: string | null;
  token: string | null;
  lease_until: number | null;
}
export interface UpdateClaim extends UpdateTask {
  stage: UpdateStage;
  status: "running";
  owner: string;
  token: string;
  lease_until: number;
}
export interface EnqueueResult {
  accepted: boolean;
  reason: "new" | "replaced" | "duplicate" | "stale" | "conflict" | "refreshed";
  task: UpdateTask;
}
export interface UpdateQueueOptions {
  clock?: () => number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  maxAttempts?: number;
}
export interface UpdateQueue {
  enqueue(draft: UpdateDraft): EnqueueResult;
  claim(stage: UpdateStage, owner: string, now?: number, leaseMs?: number): UpdateClaim | null;
  complete(claim: UpdateClaim, now?: number): boolean;
  fail(claim: UpdateClaim, now?: number): boolean;
  isCurrent(claim: UpdateClaim, now?: number): boolean;
  get(intelId: string): UpdateTask | null;
  list(): UpdateTask[];
  revoke(intelId: string, intelEventSeq: number, now?: number): boolean;
  close(): void;
}
const copy = <T>(v: T): T => structuredClone(v);
const sameRefs = (a: string[], b: string[]): boolean => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
function time(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("invalid timestamp");
  return n;
}
function positive(n: number): number {
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("invalid positive duration");
  return n;
}
function draftOf(d: UpdateDraft): UpdateDraft & { priority: number } {
  if (!d.intel_id?.trim() || !d.input_hash?.trim() || !Array.isArray(d.refs)
    || d.refs.some(r => typeof r !== "string" || !r.trim())
    || !Number.isSafeInteger(d.intel_event_seq) || d.intel_event_seq <= 0)
    throw new Error("invalid update reference/version");
  if (d.refresh_key !== undefined && (typeof d.refresh_key !== "string" || !d.refresh_key.trim()))
    throw new Error("invalid refresh key");
  const priority = d.priority ?? 0;
  if (!Number.isFinite(priority)) throw new Error("invalid priority");
  // Explicit allowlist: extra IntelItem/private fields never reach persistence.
  return { intel_id: d.intel_id, input_hash: d.input_hash,
    intel_event_seq: d.intel_event_seq, refs: [...new Set(d.refs)],
    ...(d.refresh_key === undefined ? {} : { refresh_key: d.refresh_key }),
    detected_at: time(d.detected_at), priority };
}
abstract class QueueBase implements UpdateQueue {
  private readonly clock: () => number;
  private readonly base: number;
  private readonly max: number;
  private readonly maxAttempts: number;
  constructor(options: UpdateQueueOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.base = positive(options.backoffBaseMs ?? 1_000);
    this.max = positive(options.backoffMaxMs ?? 300_000);
    this.maxAttempts = positive(options.maxAttempts ?? 5);
    if (this.max < this.base) throw new Error("backoff max below base");
  }
  protected abstract atomic<T>(fn: () => T): T;
  protected abstract load(id: string): UpdateTask | null;
  protected abstract all(): UpdateTask[];
  protected abstract save(task: UpdateTask, expected: number | null): void;
  abstract close(): void;
  get(id: string): UpdateTask | null { return this.load(id); }
  list(): UpdateTask[] { return this.all(); }
  revoke(id: string, seq: number, now = this.clock()): boolean {
    positive(seq); time(now);
    return this.atomic(() => {
      const old = this.load(id);
      if (!old || seq < old.intel_event_seq || (old.revoked_seq !== null && seq <= old.revoked_seq)) return false;
      this.save({ ...old, status: "revoked", revoked_seq: seq, revoked_at: now,
        owner: null, token: null, lease_until: null, revision: old.revision + 1 }, old.revision);
      return true;
    });
  }
  enqueue(draft: UpdateDraft): EnqueueResult {
    const d = draftOf(draft), now = time(this.clock());
    return this.atomic(() => {
      const old = this.load(d.intel_id);
      if (old?.revoked_seq !== null && old?.revoked_seq !== undefined && d.intel_event_seq <= old.revoked_seq)
        return { accepted: false, reason: "stale", task: old };
      const refresh = !!old && d.intel_event_seq === old.intel_event_seq
        && (old.status === "done" || old.status === "blocked")
        && !!d.refresh_key && d.refresh_key !== old.refresh_key
        && d.input_hash === old.input_hash && sameRefs(d.refs, old.refs);
      if (old && d.intel_event_seq <= old.intel_event_seq && !refresh) {
        const reason = d.intel_event_seq < old.intel_event_seq ? "stale"
          : d.input_hash === old.input_hash && sameRefs(d.refs, old.refs)
          ? "duplicate" : "conflict";
        return { accepted: false, reason, task: old };
      }
      const task: UpdateTask = { ...d, revision: (old?.revision ?? 0) + 1,
        stage: "enrich", status: "pending", revoked_seq: null, revoked_at: null, enqueued_at: now, started_at: null,
        enriched_at: null, index_started_at: null, indexed_at: null,
        next_attempt_at: now, attempts: 0, owner: null, token: null, lease_until: null };
      this.save(task, old?.revision ?? null);
      return { accepted: true, reason: refresh ? "refreshed" : old ? "replaced" : "new", task: copy(task) };
    });
  }
  claim(stage: UpdateStage, owner: string, now = this.clock(), leaseMs = 60_000): UpdateClaim | null {
    time(now); positive(leaseMs); time(now + leaseMs);
    if ((stage !== "enrich" && stage !== "index") || !owner.trim()) throw new Error("invalid claim");
    return this.atomic(() => {
      const candidates = this.all().filter(t => t.stage === stage && t.next_attempt_at <= now
        && (t.status === "pending" || (t.status === "running" && t.lease_until! <= now)))
        .sort((a,b) => b.intel_event_seq - a.intel_event_seq || b.priority - a.priority
          || a.enqueued_at - b.enqueued_at || a.intel_id.localeCompare(b.intel_id));
      for (const exhausted of candidates.filter(t => t.attempts >= this.maxAttempts))
        this.save({ ...exhausted, status: "blocked", owner: null, token: null, lease_until: null,
          revision: exhausted.revision + 1 }, exhausted.revision);
      const task = candidates.find(t => t.attempts < this.maxAttempts);
      if (!task) return null;
      const claimed: UpdateClaim = { ...task, stage, status: "running", owner,
        token: randomUUID(), lease_until: now + leaseMs, attempts: task.attempts + 1,
        revision: task.revision + 1, started_at: task.started_at ?? now,
        index_started_at: stage === "index" ? task.index_started_at ?? now : task.index_started_at };
      this.save(claimed, task.revision);
      return copy(claimed);
    });
  }
  private current(c: UpdateClaim, t: UpdateTask | null, now: number): t is UpdateTask {
    return !!t && t.status === "running" && t.stage === c.stage
      && t.intel_event_seq === c.intel_event_seq && t.input_hash === c.input_hash
      && t.token === c.token && t.owner === c.owner && t.revision === c.revision
      && t.lease_until !== null && t.lease_until > now;
  }
  isCurrent(c: UpdateClaim, now = this.clock()): boolean {
    time(now); return this.current(c, this.load(c.intel_id), now);
  }
  complete(c: UpdateClaim, now = this.clock()): boolean {
    time(now);
    return this.atomic(() => {
      const t = this.load(c.intel_id);
      if (!this.current(c, t, now)) return false;
      const next: UpdateTask = { ...t, revision: t.revision + 1, owner: null, token: null,
        lease_until: null, attempts: 0, next_attempt_at: now,
        stage: c.stage === "enrich" ? "index" : "done",
        status: c.stage === "enrich" ? "pending" : "done",
        enriched_at: c.stage === "enrich" ? now : t.enriched_at,
        indexed_at: c.stage === "index" ? now : null };
      this.save(next, t.revision); return true;
    });
  }
  fail(c: UpdateClaim, now = this.clock()): boolean {
    time(now);
    return this.atomic(() => {
      const t = this.load(c.intel_id);
      if (!this.current(c, t, now)) return false;
      const delay = Math.min(this.max, this.base * 2 ** Math.min(52, t.attempts - 1));
      const next: UpdateTask = { ...t, revision: t.revision + 1, status: t.attempts >= this.maxAttempts ? "blocked" : "pending",
        owner: null, token: null, lease_until: null, next_attempt_at: time(now + delay) };
      this.save(next, t.revision); return true;
    });
  }
}
export class MemoryUpdateQueue extends QueueBase {
  private readonly tasks = new Map<string, UpdateTask>();
  protected atomic<T>(fn: () => T): T { return fn(); }
  protected load(id: string): UpdateTask | null { const t = this.tasks.get(id); return t ? copy(t) : null; }
  protected all(): UpdateTask[] { return [...this.tasks.values()].map(copy); }
  protected save(t: UpdateTask, expected: number | null): void {
    if ((this.tasks.get(t.intel_id)?.revision ?? null) !== expected) throw new Error("queue CAS conflict");
    this.tasks.set(t.intel_id, copy(t));
  }
  close(): void {}
}
export class SQLiteUpdateQueue extends QueueBase {
  private readonly db: DatabaseSync;
  constructor(path: string, options: UpdateQueueOptions = {}) {
    super(options);
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;");
    this.db.exec(`CREATE TABLE IF NOT EXISTS agent_update_queue (
      intel_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload TEXT NOT NULL
    )`);
  }
  protected atomic<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const result = fn(); this.db.exec("COMMIT"); return result; }
    catch (e) { this.db.exec("ROLLBACK"); throw e; }
  }
  protected load(id: string): UpdateTask | null {
    const row = this.db.prepare("SELECT payload FROM agent_update_queue WHERE intel_id=?").get(id);
    return row ? JSON.parse(row.payload as string) as UpdateTask : null;
  }
  protected all(): UpdateTask[] {
    return this.db.prepare("SELECT payload FROM agent_update_queue").all()
      .map(row => JSON.parse(row.payload as string) as UpdateTask);
  }
  protected save(t: UpdateTask, expected: number | null): void {
    const result = expected === null
      ? this.db.prepare("INSERT INTO agent_update_queue(intel_id,revision,payload) VALUES(?,?,?)")
        .run(t.intel_id, t.revision, JSON.stringify(t))
      : this.db.prepare("UPDATE agent_update_queue SET revision=?,payload=? WHERE intel_id=? AND revision=?")
        .run(t.revision, JSON.stringify(t), t.intel_id, expected);
    if (Number(result.changes) !== 1) throw new Error("queue CAS conflict");
  }
  close(): void { this.db.close(); }
}
