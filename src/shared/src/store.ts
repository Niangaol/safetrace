/**
 * 持久化存储抽象（S2 v0）。
 * 本地默认 SQLite（Node 24 内置 node:sqlite，免原生编译）；
 * compose 起 PostgreSQL 后同一接口切 Postgres（实现类随后补）。
 * 事件表按 event_id 幂等去重；死信自动重试 3 次后留档。
 */
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { Envelope, Topic } from "./envelope.js";
import type { QualityVerdict } from "./types.js";

export type LineageStatus = "success" | "degraded" | "rejected" | "review" | "failed";
export interface LineageArtifactRef { kind: string; id: string; sha256?: string; url?: string }
export interface LineageRecord {
  lineage_id: string;
  trace_id: string;
  parent_lineage_ids: string[];
  causation_id: string | null;
  stage: string;
  operation_version: string;
  status: LineageStatus;
  started_at: string;
  completed_at: string;
  recorded_at: string;
  input_refs: LineageArtifactRef[];
  output_refs: LineageArtifactRef[];
  source?: { source_id?: string; source_type?: string; url?: string; fetched_at?: string; etag?: string };
  execution?: { component_version?: string; provider?: string; model_id?: string; model_version?: string; config_sha256?: string; prompt_sha256?: string; latency_ms?: number; cached?: boolean; input_tokens?: number; output_tokens?: number; vector_dimension?: number };
  decision?: { reason?: string; fallback_to?: string; review_required?: boolean; quality_score?: number };
  error?: string;
}
export interface StoredPageSnapshot {
  source_url: string;
  final_url: string;
  title: string;
  text: string;
  fetched_at: string;
  provider: "direct" | "firecrawl";
  content_sha256: string;
  lineage_ids: string[];
}

export type ReviewCaseStatus = "pending" | "deferred" | "accepted" | "rejected";
export interface ReviewCaseDraft {
  review_id: string;
  trace_id: string;
  source_url: string;
  page_sha256: string;
  title: string;
  reason: string;
  candidate_sha256?: string;
  lineage_id: string;
  created_at: string;
}
export interface ReviewCase extends ReviewCaseDraft {
  status: ReviewCaseStatus;
  updated_at: string;
  reviewer_id?: string;
  rationale?: string;
  decision_lineage_id?: string;
}
export interface ReviewCaseDecision {
  review_id: string;
  trace_id: string;
  action: "deferred" | "accepted" | "rejected";
  reviewer_id: string;
  rationale: string;
  lineage_id: string;
  recorded_at: string;
}
/**
 * E-04：DQ1 隔离区记录。verdict=quarantine 的判定此前只有 dq.verdicts 事件一种形态，
 * 无表无目录、不可查不可导出；本记录照 dead_letters 模式落库， verdict 原样留存可复算。
 */
export interface QuarantineRecord {
  /** dq1 产出的 quarantine_ref（dq_quarantine:<intel_id>），幂等键。 */
  quarantine_ref: string;
  intel_id: string;
  /** 人类可读的隔离原因（红线标记或质量分不足）。 */
  reason: string;
  /** 完整判定（原样 JSON，含 dimension_scores/flags/gate_version，可复算）。 */
  verdict: QualityVerdict;
  quarantined_at: string;
}

/**
 * A-01：编排线程检查点（statemachine 挂起/恢复的持久化形态）。
 * spec 含函数不可序列化，故只持久化「进度 + 状态快照」；resume 时由调用方提供同一 spec。
 * 恢复值不落库——它由 resume 调用方当场给出（resume(threadId, value) 的 value）。
 */
export interface ThreadCheckpoint {
  thread_id: string;
  trace_id: string;
  /** 已执行节点 id（resume 时跳过，不重跑）。 */
  executed: string[];
  /** 挂起节点 id（resume 后第一个执行的节点）；completed 时为完成时的最后节点。 */
  interrupt_node_id: string;
  /** 可序列化状态快照（挂起点或完成点的 machine state）。 */
  state: Record<string, unknown>;
  status: "suspended" | "completed";
  updated_at: string;
}

export interface LineageDraft {
  trace_id: string;
  stage: string;
  operation_version: string;
  status: LineageStatus;
  parent_lineage_ids?: string[];
  causation_id?: string | null;
  started_at?: string;
  completed_at?: string;
  input_refs?: LineageArtifactRef[];
  output_refs?: LineageArtifactRef[];
  source?: LineageRecord["source"];
  execution?: LineageRecord["execution"];
  decision?: LineageRecord["decision"];
  error?: string;
}

export interface IntelAdmissionEvent { seq:number;event_id:string;trace_id:string;causation_id:string|null;topic:"raw.docs"|"intel.items"|"dq.verdicts";payload:unknown }

function intelAdmissionRows(db: DatabaseSync): IntelAdmissionEvent[] {
  return db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('raw.docs','intel.items','dq.verdicts') ORDER BY seq").all().map(row=>({seq:Number(row.seq),event_id:String(row.event_id),trace_id:String(row.trace_id),causation_id:row.causation_id===null?null:String(row.causation_id),topic:row.topic as IntelAdmissionEvent["topic"],payload:JSON.parse(String(row.payload))}));
}

export interface EventStore {
  /** 写入事件。返回是否为新事件（false = 重复投递被幂等去重）。 */
  append<T>(env: Envelope<T>): Promise<boolean>;
  /** 按主题顺序读取（offset 分页）。 */
  read<T>(topic: Topic, offset?: number, limit?: number): Promise<Envelope<T>[]>;
  /** One globally ordered Intel/DQ snapshot, not independently paginated topic views. */
  readIntelAdmissionEvents?(): IntelAdmissionEvent[];
  /** Synchronous cross-store work while Intel writers are reserved; no Intel content is written. */
  withIntelAdmissionSnapshot?<T>(operation:(events:IntelAdmissionEvent[])=>T): T;
  /** 标记事件为死信（超过重投上限）。 */
  markDeadLetter(eventId: string, reason: string): Promise<void>;
  /** 死信队列内容（A1 看板消费）。 */
  deadLetters(): Promise<Array<{ event_id: string; reason: string; envelope: Envelope }>>;
  /** 死信重投成功后的销档（A-06 selfheal dead_letter_drain 消费）。 */
  clearDeadLetter(eventId: string): Promise<void>;
  /** E-04：隔离区落库（DQ1 verdict=quarantine 的审计留存；照 dead_letters 模式）。 */
  markQuarantine(record: QuarantineRecord): Promise<void>;
  /** 隔离区内容（可查可导出；A1/S1 看板与运维脚本消费）。 */
  quarantineEntries(): Promise<QuarantineRecord[]>;
  /** A-01：保存编排线程检查点（挂起/完成；幂等按 thread_id）。 */
  saveThreadCheckpoint(checkpoint: ThreadCheckpoint): Promise<void>;
  /** A-01：读取编排线程检查点；不存在返回 undefined。 */
  loadThreadCheckpoint(threadId: string): Promise<ThreadCheckpoint | undefined>;
  /** A-01：全部线程检查点（运维查看挂起/已完成线程）。 */
  threadCheckpoints(): Promise<ThreadCheckpoint[]>;
  appendLineage(record: LineageRecord): Promise<boolean>;
  readLineage(traceId: string, offset?: number, limit?: number): Promise<LineageRecord[]>;
  getLastGoodPageSnapshot(sourceUrl: string): Promise<StoredPageSnapshot | undefined>;
  saveLastGoodPageSnapshot(snapshot: StoredPageSnapshot): Promise<boolean>;
  getLastGoodPageSnapshotByHash(contentSha256: string): Promise<StoredPageSnapshot | undefined>;
  enqueueReviewCase(review: ReviewCaseDraft): Promise<boolean>;
  getReviewCase(reviewId: string): Promise<ReviewCase | undefined>;
  listPendingReviewCases(offset?: number, limit?: number): Promise<ReviewCase[]>;
  appendReviewCaseDecision(decision: ReviewCaseDecision): Promise<boolean>;
  close(): void;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS events (
  event_id     TEXT PRIMARY KEY,
  topic        TEXT NOT NULL,
  occurred_at  TEXT NOT NULL,
  trace_id     TEXT NOT NULL,
  causation_id TEXT,
  payload      TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  seq          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_topic_seq ON events(topic, seq);
CREATE TABLE IF NOT EXISTS lineage_records (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  lineage_id TEXT NOT NULL UNIQUE,
  trace_id TEXT NOT NULL,
  parent_lineage_ids TEXT NOT NULL,
  stage TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lineage_trace_seq ON lineage_records(trace_id, seq);
CREATE TABLE IF NOT EXISTS last_good_pages (
  source_url TEXT PRIMARY KEY,
  final_url TEXT NOT NULL,
  title TEXT NOT NULL,
  text TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  provider TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  lineage_ids TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS page_snapshot_history (
  source_url TEXT NOT NULL,
  final_url TEXT NOT NULL,
  title TEXT NOT NULL,
  text TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  provider TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  lineage_ids TEXT NOT NULL,
  PRIMARY KEY (source_url, content_sha256)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_history_hash ON page_snapshot_history(content_sha256);
INSERT OR IGNORE INTO page_snapshot_history
  SELECT source_url, final_url, title, text, fetched_at, provider, content_sha256, lineage_ids FROM last_good_pages;
CREATE TABLE IF NOT EXISTS review_cases (
  review_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  source_url TEXT NOT NULL,
  page_sha256 TEXT NOT NULL,
  title TEXT NOT NULL,
  reason TEXT NOT NULL,
  candidate_sha256 TEXT,
  lineage_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS review_case_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  action TEXT NOT NULL,
  reviewer_id TEXT,
  rationale TEXT,
  lineage_id TEXT NOT NULL,
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_case_event_seq ON review_case_events(review_id, seq);
CREATE TABLE IF NOT EXISTS dead_letters (
  event_id  TEXT PRIMARY KEY,
  reason    TEXT NOT NULL,
  envelope  TEXT NOT NULL,
  failed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
  quarantine_ref TEXT PRIMARY KEY,
  intel_id       TEXT NOT NULL,
  reason         TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  quarantined_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_threads (
  thread_id        TEXT PRIMARY KEY,
  trace_id         TEXT NOT NULL,
  executed         TEXT NOT NULL,
  interrupt_node_id TEXT NOT NULL,
  state            TEXT NOT NULL,
  status           TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
`;

export class SqliteEventStore implements EventStore {
  private db: DatabaseSync;
  readIntelAdmissionEvents(): IntelAdmissionEvent[] { return intelAdmissionRows(this.db); }
  withIntelAdmissionSnapshot<T>(operation:(events:IntelAdmissionEvent[])=>T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const result=operation(this.readIntelAdmissionEvents());this.db.exec("COMMIT");return result; }
    catch(error){this.db.exec("ROLLBACK");throw error;}
  }

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout = 5000");
    this.db.exec(SCHEMA_SQL);
    // 兼容旧库：串行迁移重复 seq，再建立全库唯一约束，防止多个 store 实例各自取 MAX(seq) 撞号。
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const duplicates = this.db.prepare("SELECT seq FROM events GROUP BY seq HAVING COUNT(*) > 1").all() as Array<{ seq: number }>;
      for (const duplicate of duplicates) {
        const rows = this.db.prepare("SELECT event_id FROM events WHERE seq = ? ORDER BY rowid").all(duplicate.seq) as Array<{ event_id: string }>;
        for (const row of rows.slice(1)) {
          const next = this.db.prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM events").get() as { n: number };
          this.db.prepare("UPDATE events SET seq = ? WHERE event_id = ?").run(next.n, row.event_id);
        }
      }
      this.db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_seq_unique ON events(seq)");
      this.db.exec("COMMIT");
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction may already be closed */ }
      throw error;
    }
  }

  async append<T>(env: Envelope<T>): Promise<boolean> {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const exists = this.db.prepare("SELECT 1 FROM events WHERE event_id = ?").get(env.event_id);
      if (exists) {
        this.db.exec("COMMIT");
        return false; // 幂等：重复投递直接吞掉
      }
      const next = this.db.prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM events").get() as { n: number };
      this.db
        .prepare(
          "INSERT INTO events (event_id, topic, occurred_at, trace_id, causation_id, payload, schema_version, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          env.event_id, env.topic, env.occurred_at, env.trace_id,
          env.causation_id, JSON.stringify(env.payload), env.schema_version, next.n,
        );
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction may already be closed */ }
      throw error;
    }
  }

  async read<T>(topic: Topic, offset = 0, limit = 100): Promise<Envelope<T>[]> {
    const rows = this.db
      .prepare("SELECT * FROM events WHERE topic = ? ORDER BY seq LIMIT ? OFFSET ?")
      .all(topic, limit, offset) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      event_id: r.event_id as string,
      topic: r.topic as Topic,
      occurred_at: r.occurred_at as string,
      trace_id: r.trace_id as string,
      causation_id: (r.causation_id as string | null) ?? null,
      payload: JSON.parse(r.payload as string) as T,
      schema_version: r.schema_version as string,
    }));
  }

  async appendLineage(record: LineageRecord): Promise<boolean> {
    const result = this.db.prepare("INSERT OR IGNORE INTO lineage_records (lineage_id, trace_id, parent_lineage_ids, stage, recorded_at, payload) VALUES (?, ?, ?, ?, ?, ?)")
      .run(record.lineage_id, record.trace_id, JSON.stringify(record.parent_lineage_ids), record.stage, record.recorded_at, JSON.stringify(record));
    return result.changes > 0;
  }

  async readLineage(traceId: string, offset = 0, limit = 100): Promise<LineageRecord[]> {
    const rows = this.db.prepare("SELECT payload FROM lineage_records WHERE trace_id = ? ORDER BY seq LIMIT ? OFFSET ?")
      .all(traceId, limit, offset) as Array<{ payload: string }>;
    return rows.map((row) => JSON.parse(row.payload) as LineageRecord);
  }

  async getLastGoodPageSnapshot(sourceUrl: string): Promise<StoredPageSnapshot | undefined> {
    const row = this.db.prepare("SELECT * FROM last_good_pages WHERE source_url = ?").get(sourceUrl) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    const snapshot: StoredPageSnapshot = {
      source_url: row.source_url as string,
      final_url: row.final_url as string,
      title: row.title as string,
      text: row.text as string,
      fetched_at: row.fetched_at as string,
      provider: row.provider as StoredPageSnapshot["provider"],
      content_sha256: row.content_sha256 as string,
      lineage_ids: JSON.parse(row.lineage_ids as string) as string[],
    };
    if (createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== snapshot.content_sha256) throw new Error("last-good page snapshot SHA-256 mismatch");
    return snapshot;
  }

  async saveLastGoodPageSnapshot(snapshot: StoredPageSnapshot): Promise<boolean> {
    if (createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== snapshot.content_sha256) throw new Error("refusing to persist a page snapshot with invalid SHA-256");
    const sql = "INSERT INTO last_good_pages (source_url, final_url, title, text, fetched_at, provider, content_sha256, lineage_ids) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(source_url) DO UPDATE SET final_url=excluded.final_url, title=excluded.title, text=excluded.text, fetched_at=excluded.fetched_at, provider=excluded.provider, content_sha256=excluded.content_sha256, lineage_ids=excluded.lineage_ids " +
      "WHERE excluded.fetched_at >= last_good_pages.fetched_at";
    const values = [snapshot.source_url, snapshot.final_url, snapshot.title, snapshot.text, snapshot.fetched_at, snapshot.provider, snapshot.content_sha256, JSON.stringify(snapshot.lineage_ids)];
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT OR IGNORE INTO page_snapshot_history (source_url, final_url, title, text, fetched_at, provider, content_sha256, lineage_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(...values);
      const result = this.db.prepare(sql).run(...values);
      this.db.exec("COMMIT");
      return result.changes > 0;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  async enqueueReviewCase(review: ReviewCaseDraft): Promise<boolean> {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const inserted = this.db.prepare("INSERT OR IGNORE INTO review_cases (review_id, trace_id, source_url, page_sha256, title, reason, candidate_sha256, lineage_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(review.review_id, review.trace_id, review.source_url, review.page_sha256, review.title, review.reason, review.candidate_sha256 ?? null, review.lineage_id, review.created_at);
      if (inserted.changes === 0) {
        this.db.exec("ROLLBACK");
        return false;
      }
      this.db.prepare("INSERT INTO review_case_events (review_id, trace_id, action, reviewer_id, rationale, lineage_id, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(review.review_id, review.trace_id, "pending", null, null, review.lineage_id, review.created_at);
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  async getReviewCase(reviewId: string): Promise<ReviewCase | undefined> {
    const base = this.db.prepare("SELECT * FROM review_cases WHERE review_id = ?").get(reviewId) as Record<string, unknown> | undefined;
    if (!base) return undefined;
    const event = this.db.prepare("SELECT * FROM review_case_events WHERE review_id = ? ORDER BY seq DESC LIMIT 1").get(reviewId) as Record<string, unknown> | undefined;
    if (!event) return undefined;
    return {
      review_id: base.review_id as string,
      trace_id: base.trace_id as string,
      source_url: base.source_url as string,
      page_sha256: base.page_sha256 as string,
      title: base.title as string,
      reason: base.reason as string,
      ...(typeof base.candidate_sha256 === "string" ? { candidate_sha256: base.candidate_sha256 } : {}),
      lineage_id: base.lineage_id as string,
      created_at: base.created_at as string,
      status: event.action as ReviewCaseStatus,
      updated_at: event.recorded_at as string,
      ...(typeof event.reviewer_id === "string" ? { reviewer_id: event.reviewer_id } : {}),
      ...(typeof event.rationale === "string" ? { rationale: event.rationale } : {}),
      ...(typeof event.lineage_id === "string" ? { decision_lineage_id: event.lineage_id } : {}),
    };
  }

  async listPendingReviewCases(offset = 0, limit = 100): Promise<ReviewCase[]> {
    const rows = this.db.prepare("SELECT c.*, e.action, e.reviewer_id, e.rationale, e.lineage_id AS decision_lineage_id, e.recorded_at AS updated_at FROM review_cases c JOIN review_case_events e ON e.seq = (SELECT MAX(latest.seq) FROM review_case_events latest WHERE latest.review_id = c.review_id) WHERE e.action IN ('pending', 'deferred') ORDER BY c.created_at LIMIT ? OFFSET ?")
      .all(limit, offset) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      review_id: row.review_id as string,
      trace_id: row.trace_id as string,
      source_url: row.source_url as string,
      page_sha256: row.page_sha256 as string,
      title: row.title as string,
      reason: row.reason as string,
      ...(typeof row.candidate_sha256 === "string" ? { candidate_sha256: row.candidate_sha256 } : {}),
      lineage_id: row.lineage_id as string,
      created_at: row.created_at as string,
      status: row.action as ReviewCaseStatus,
      updated_at: row.updated_at as string,
      ...(typeof row.reviewer_id === "string" ? { reviewer_id: row.reviewer_id } : {}),
      ...(typeof row.rationale === "string" ? { rationale: row.rationale } : {}),
      ...(typeof row.decision_lineage_id === "string" ? { decision_lineage_id: row.decision_lineage_id } : {}),
    }));
  }

  async appendReviewCaseDecision(decision: ReviewCaseDecision): Promise<boolean> {
    const current = await this.getReviewCase(decision.review_id);
    if (!current || current.status === "accepted" || current.status === "rejected") return false;
    const result = this.db.prepare("INSERT INTO review_case_events (review_id, trace_id, action, reviewer_id, rationale, lineage_id, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(decision.review_id, decision.trace_id, decision.action, decision.reviewer_id, decision.rationale, decision.lineage_id, decision.recorded_at);
    return result.changes > 0;
  }

  async getLastGoodPageSnapshotByHash(contentSha256: string): Promise<StoredPageSnapshot | undefined> {
    const row = this.db.prepare("SELECT * FROM page_snapshot_history WHERE content_sha256 = ? ORDER BY fetched_at DESC LIMIT 1").get(contentSha256) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    const snapshot: StoredPageSnapshot = {
      source_url: row.source_url as string, final_url: row.final_url as string,
      title: row.title as string, text: row.text as string,
      fetched_at: row.fetched_at as string, provider: row.provider as StoredPageSnapshot["provider"],
      content_sha256: row.content_sha256 as string, lineage_ids: JSON.parse(row.lineage_ids as string) as string[],
    };
    if (createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== contentSha256) throw new Error("historical page snapshot SHA-256 mismatch");
    return snapshot;
  }

  async markDeadLetter(eventId: string, reason: string): Promise<void> {
    const row = this.db.prepare("SELECT * FROM events WHERE event_id = ?").get(event_id(eventId)) as Record<string, unknown> | undefined;
    if (!row) return;
    this.db
      .prepare("INSERT OR REPLACE INTO dead_letters (event_id, reason, envelope, failed_at) VALUES (?, ?, ?, ?)")
      .run(eventId, reason, JSON.stringify(toEnvelope(row)), new Date().toISOString());
  }

  async deadLetters() {
    const rows = this.db.prepare("SELECT * FROM dead_letters ORDER BY failed_at").all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      event_id: r.event_id as string,
      reason: r.reason as string,
      envelope: JSON.parse(r.envelope as string) as Envelope,
    }));
  }

  async clearDeadLetter(eventId: string): Promise<void> {
    this.db.prepare("DELETE FROM dead_letters WHERE event_id = ?").run(eventId);
  }

  async markQuarantine(record: QuarantineRecord): Promise<void> {
    this.db
      .prepare("INSERT OR REPLACE INTO quarantine (quarantine_ref, intel_id, reason, verdict, quarantined_at) VALUES (?, ?, ?, ?, ?)")
      .run(record.quarantine_ref, record.intel_id, record.reason, JSON.stringify(record.verdict), record.quarantined_at);
  }

  async quarantineEntries(): Promise<QuarantineRecord[]> {
    const rows = this.db.prepare("SELECT * FROM quarantine ORDER BY quarantined_at").all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      quarantine_ref: r.quarantine_ref as string,
      intel_id: r.intel_id as string,
      reason: r.reason as string,
      verdict: JSON.parse(r.verdict as string) as QualityVerdict,
      quarantined_at: r.quarantined_at as string,
    }));
  }

  async saveThreadCheckpoint(checkpoint: ThreadCheckpoint): Promise<void> {
    this.db
      .prepare("INSERT OR REPLACE INTO machine_threads (thread_id, trace_id, executed, interrupt_node_id, state, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(checkpoint.thread_id, checkpoint.trace_id, JSON.stringify(checkpoint.executed), checkpoint.interrupt_node_id, JSON.stringify(checkpoint.state), checkpoint.status, checkpoint.updated_at);
  }

  async loadThreadCheckpoint(threadId: string): Promise<ThreadCheckpoint | undefined> {
    const row = this.db.prepare("SELECT * FROM machine_threads WHERE thread_id = ?").get(threadId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      thread_id: row.thread_id as string,
      trace_id: row.trace_id as string,
      executed: JSON.parse(row.executed as string) as string[],
      interrupt_node_id: row.interrupt_node_id as string,
      state: JSON.parse(row.state as string) as Record<string, unknown>,
      status: row.status as ThreadCheckpoint["status"],
      updated_at: row.updated_at as string,
    };
  }

  async threadCheckpoints(): Promise<ThreadCheckpoint[]> {
    const rows = this.db.prepare("SELECT * FROM machine_threads ORDER BY updated_at").all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      thread_id: r.thread_id as string,
      trace_id: r.trace_id as string,
      executed: JSON.parse(r.executed as string) as string[],
      interrupt_node_id: r.interrupt_node_id as string,
      state: JSON.parse(r.state as string) as Record<string, unknown>,
      status: r.status as ThreadCheckpoint["status"],
      updated_at: r.updated_at as string,
    }));
  }

  close(): void {
    this.db.close();
  }
}

function event_id(v: string): string { return v; }
function toEnvelope(row: Record<string, unknown>): Envelope {
  return {
    event_id: row.event_id as string,
    topic: row.topic as Topic,
    occurred_at: row.occurred_at as string,
    trace_id: row.trace_id as string,
    causation_id: (row.causation_id as string | null) ?? null,
    payload: JSON.parse(row.payload as string),
    schema_version: row.schema_version as string,
  };
}

/** 内存实现：单测与冒烟零依赖运行。 */
export class MemoryEventStore implements EventStore {
  private events: Envelope[] = [];
  readIntelAdmissionEvents(): IntelAdmissionEvent[] {
    return this.events.map((event,index)=>({...structuredClone(event),seq:index+1})).filter(e=>["raw.docs","intel.items","dq.verdicts"].includes(e.topic)) as IntelAdmissionEvent[];
  }
  withIntelAdmissionSnapshot<T>(operation:(events:IntelAdmissionEvent[])=>T): T { return operation(this.readIntelAdmissionEvents()); }
  private dead: Array<{ event_id: string; reason: string; envelope: Envelope }> = [];
  private lineage: LineageRecord[] = [];
  private lastGoodPages = new Map<string, StoredPageSnapshot>();
  private pageHistory = new Map<string, StoredPageSnapshot>();
  private reviewCases = new Map<string, ReviewCase>();

  async append<T>(env: Envelope<T>): Promise<boolean> {
    if (this.events.some((e) => e.event_id === env.event_id)) return false;
    this.events.push(env as Envelope);
    return true;
  }

  async read<T>(topic: Topic, offset = 0, limit = 100): Promise<Envelope<T>[]> {
    return this.events
      .filter((e) => e.topic === topic)
      .slice(offset, offset + limit) as unknown as Envelope<T>[];
  }

  async appendLineage(record: LineageRecord): Promise<boolean> {
    if (this.lineage.some((item) => item.lineage_id === record.lineage_id)) return false;
    this.lineage.push(record);
    return true;
  }

  async readLineage(traceId: string, offset = 0, limit = 100): Promise<LineageRecord[]> {
    return this.lineage.filter((item) => item.trace_id === traceId).slice(offset, offset + limit);
  }

  async getLastGoodPageSnapshot(sourceUrl: string): Promise<StoredPageSnapshot | undefined> {
    const row = this.lastGoodPages.get(sourceUrl);
    if (!row) return undefined;
    const snapshot = row;
    if (createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== snapshot.content_sha256) throw new Error("last-good page snapshot SHA-256 mismatch");
    return { ...snapshot, lineage_ids: [...snapshot.lineage_ids] };
  }

  async saveLastGoodPageSnapshot(snapshot: StoredPageSnapshot): Promise<boolean> {
    if (createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== snapshot.content_sha256) throw new Error("refusing to persist a page snapshot with invalid SHA-256");
    const historyKey = snapshot.source_url + "|" + snapshot.content_sha256;
    if (!this.pageHistory.has(historyKey)) this.pageHistory.set(historyKey, { ...snapshot, lineage_ids: [...snapshot.lineage_ids] });
    const previous = this.lastGoodPages.get(snapshot.source_url);
    if (previous && previous.fetched_at > snapshot.fetched_at) return false;
    this.lastGoodPages.set(snapshot.source_url, { ...snapshot, lineage_ids: [...snapshot.lineage_ids] });
    return true;
  }

  async enqueueReviewCase(review: ReviewCaseDraft): Promise<boolean> {
    if (this.reviewCases.has(review.review_id)) return false;
    this.reviewCases.set(review.review_id, { ...review, status: "pending", updated_at: review.created_at });
    return true;
  }

  async getReviewCase(reviewId: string): Promise<ReviewCase | undefined> {
    const review = this.reviewCases.get(reviewId);
    return review ? { ...review } : undefined;
  }

  async listPendingReviewCases(offset = 0, limit = 100): Promise<ReviewCase[]> {
    return [...this.reviewCases.values()].filter((review) => review.status === "pending" || review.status === "deferred")
      .slice(offset, offset + limit).map((review) => ({ ...review }));
  }

  async appendReviewCaseDecision(decision: ReviewCaseDecision): Promise<boolean> {
    const review = this.reviewCases.get(decision.review_id);
    if (!review || review.status === "accepted" || review.status === "rejected") return false;
    this.reviewCases.set(decision.review_id, {
      ...review,
      status: decision.action,
      updated_at: decision.recorded_at,
      reviewer_id: decision.reviewer_id,
      rationale: decision.rationale,
      decision_lineage_id: decision.lineage_id,
    });
    return true;
  }

  async getLastGoodPageSnapshotByHash(contentSha256: string): Promise<StoredPageSnapshot | undefined> {
    const snapshot = [...this.pageHistory.values()].find((candidate) => candidate.content_sha256 === contentSha256);
    if (snapshot && createHash("sha256").update(snapshot.text, "utf8").digest("hex") !== contentSha256) throw new Error("historical page snapshot SHA-256 mismatch");
    return snapshot ? { ...snapshot, lineage_ids: [...snapshot.lineage_ids] } : undefined;
  }

  async markDeadLetter(eventId: string, reason: string): Promise<void> {
    const env = this.events.find((e) => e.event_id === eventId);
    if (!env) return;
    if (!this.dead.some((d) => d.event_id === eventId)) {
      this.dead.push({ event_id: eventId, reason, envelope: env });
    }
  }

  async deadLetters() {
    return [...this.dead];
  }

  async clearDeadLetter(eventId: string): Promise<void> {
    this.dead = this.dead.filter((d) => d.event_id !== eventId);
  }

  private quarantined: QuarantineRecord[] = [];

  async markQuarantine(record: QuarantineRecord): Promise<void> {
    const existing = this.quarantined.findIndex((q) => q.quarantine_ref === record.quarantine_ref);
    if (existing >= 0) this.quarantined[existing] = record;
    else this.quarantined.push(record);
  }

  async quarantineEntries(): Promise<QuarantineRecord[]> {
    return [...this.quarantined];
  }

  private threads = new Map<string, ThreadCheckpoint>();

  async saveThreadCheckpoint(checkpoint: ThreadCheckpoint): Promise<void> {
    this.threads.set(checkpoint.thread_id, {
      ...checkpoint,
      executed: [...checkpoint.executed],
      state: structuredClone(checkpoint.state),
    });
  }

  async loadThreadCheckpoint(threadId: string): Promise<ThreadCheckpoint | undefined> {
    const row = this.threads.get(threadId);
    return row ? { ...row, executed: [...row.executed], state: structuredClone(row.state) } : undefined;
  }

  async threadCheckpoints(): Promise<ThreadCheckpoint[]> {
    return [...this.threads.values()].map((row) => ({ ...row, executed: [...row.executed], state: structuredClone(row.state) }));
  }

  close(): void { /* 内存实现无资源可释放 */ }
}
