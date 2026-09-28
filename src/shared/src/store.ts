/**
 * 持久化存储抽象（S2 v0）。
 * 本地默认 SQLite（Node 24 内置 node:sqlite，免原生编译）；
 * compose 起 PostgreSQL 后同一接口切 Postgres（实现类随后补）。
 * 事件表按 event_id 幂等去重；死信自动重试 3 次后留档。
 */
import { DatabaseSync } from "node:sqlite";
import type { Envelope, Topic } from "./envelope.js";

export interface EventStore {
  /** 写入事件。返回是否为新事件（false = 重复投递被幂等去重）。 */
  append<T>(env: Envelope<T>): Promise<boolean>;
  /** 按主题顺序读取（offset 分页）。 */
  read<T>(topic: Topic, offset?: number, limit?: number): Promise<Envelope<T>[]>;
  /** 标记事件为死信（超过重试上限）。 */
  markDeadLetter(eventId: string, reason: string): Promise<void>;
  /** 死信队列内容（A1 看板消费）。 */
  deadLetters(): Promise<Array<{ event_id: string; reason: string; envelope: Envelope }>>;
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
CREATE TABLE IF NOT EXISTS dead_letters (
  event_id  TEXT PRIMARY KEY,
  reason    TEXT NOT NULL,
  envelope  TEXT NOT NULL,
  failed_at TEXT NOT NULL
);
`;

export class SqliteEventStore implements EventStore {
  private db: DatabaseSync;
  private seq = 0;

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA_SQL);
    const row = this.db.prepare("SELECT COALESCE(MAX(seq), 0) AS m FROM events").get() as { m: number };
    this.seq = row.m;
  }

  async append<T>(env: Envelope<T>): Promise<boolean> {
    const exists = this.db.prepare("SELECT 1 FROM events WHERE event_id = ?").get(env.event_id);
    if (exists) return false; // 幂等：重复投递直接吞掉
    this.seq += 1;
    this.db
      .prepare(
        "INSERT INTO events (event_id, topic, occurred_at, trace_id, causation_id, payload, schema_version, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        env.event_id, env.topic, env.occurred_at, env.trace_id,
        env.causation_id, JSON.stringify(env.payload), env.schema_version, this.seq,
      );
    return true;
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
  private dead: Array<{ event_id: string; reason: string; envelope: Envelope }> = [];

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

  close(): void { /* 内存实现无资源可释放 */ }
}
