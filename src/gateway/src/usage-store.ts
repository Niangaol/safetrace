/**
 * 计量落库（MG1 职责 5）：每次调用记录 provider/模型/token/延迟/是否降级。
 * 内存实现（默认）+ SQLite 持久化（可选路径）。
 */
import { DatabaseSync } from "node:sqlite";
import type { UsageRecord } from "./types.js";

export interface UsageStore {
  record(r: UsageRecord): Promise<void>;
  query(filter?: { role?: string; provider?: string }): Promise<UsageRecord[]>;
  totals(): Promise<{ calls: number; prompt_tokens: number; completion_tokens: number; degraded: number }>;
  close(): void;
}

export class MemoryUsageStore implements UsageStore {
  private rows: UsageRecord[] = [];

  async record(r: UsageRecord): Promise<void> {
    this.rows.push(r);
  }

  async query(filter: { role?: string; provider?: string } = {}): Promise<UsageRecord[]> {
    return this.rows.filter(
      (r) => (!filter.role || r.role === filter.role) && (!filter.provider || r.provider === filter.provider),
    );
  }

  async totals() {
    return {
      calls: this.rows.length,
      prompt_tokens: this.rows.reduce((s, r) => s + r.prompt_tokens, 0),
      completion_tokens: this.rows.reduce((s, r) => s + r.completion_tokens, 0),
      degraded: this.rows.filter((r) => r.degraded_to !== "").length,
    };
  }

  close(): void { /* 内存实现无资源 */ }
}

const USAGE_SCHEMA = [
  "CREATE TABLE IF NOT EXISTS usage (",
  "  ts TEXT NOT NULL, role TEXT NOT NULL, provider TEXT NOT NULL, model_id TEXT NOT NULL,",
  "  call TEXT NOT NULL, prompt_tokens INTEGER NOT NULL, completion_tokens INTEGER NOT NULL,",
  "  latency_ms INTEGER NOT NULL, cached INTEGER NOT NULL, degraded_to TEXT NOT NULL, trace_id TEXT NOT NULL",
  ");",
  "CREATE INDEX IF NOT EXISTS idx_usage_role ON usage(role);",
].join("\n");

export class SqliteUsageStore implements UsageStore {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(USAGE_SCHEMA);
  }

  async record(r: UsageRecord): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO usage (ts, role, provider, model_id, call, prompt_tokens, completion_tokens, latency_ms, cached, degraded_to, trace_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        r.ts, r.role, r.provider, r.model_id, r.call, r.prompt_tokens, r.completion_tokens,
        r.latency_ms, r.cached ? 1 : 0, r.degraded_to, r.trace_id,
      );
  }

  async query(filter: { role?: string; provider?: string } = {}): Promise<UsageRecord[]> {
    const clauses: string[] = [];
    const args: string[] = [];
    if (filter.role) { clauses.push("role = ?"); args.push(filter.role); }
    if (filter.provider) { clauses.push("provider = ?"); args.push(filter.provider); }
    const where = clauses.length ? " WHERE " + clauses.join(" AND ") : "";
    const rows = this.db.prepare("SELECT * FROM usage" + where + " ORDER BY ts").all(...args) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      ts: r.ts as string, role: r.role as string, provider: r.provider as string,
      model_id: r.model_id as string, call: r.call as UsageRecord["call"],
      prompt_tokens: Number(r.prompt_tokens), completion_tokens: Number(r.completion_tokens),
      latency_ms: Number(r.latency_ms), cached: Boolean(r.cached),
      degraded_to: r.degraded_to as string, trace_id: r.trace_id as string,
    }));
  }

  async totals() {
    const row = this.db
      .prepare("SELECT COUNT(*) AS calls, COALESCE(SUM(prompt_tokens),0) AS pt, COALESCE(SUM(completion_tokens),0) AS ct FROM usage")
      .get() as { calls: number; pt: number; ct: number };
    // 用 length() 判空，避免在单引号 JS 字符串里嵌套 SQL 引号
    const degradedRow = this.db
      .prepare("SELECT COUNT(*) AS d FROM usage WHERE length(degraded_to) > 0")
      .get() as { d: number };
    return {
      calls: Number(row.calls),
      prompt_tokens: Number(row.pt),
      completion_tokens: Number(row.ct),
      degraded: Number(degradedRow.d),
    };
  }

  close(): void {
    this.db.close();
  }
}
