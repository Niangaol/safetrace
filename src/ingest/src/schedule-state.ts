/** Local scheduling metadata; deliberately separate from the shared event schema. */
import { DatabaseSync } from "node:sqlite";

export type SourceRunStatus = "complete" | "partial" | "truncated" | "fixture" | "no_data" | "failed";
export interface SourceScheduleState {
  source_id: string;
  last_attempt_at: string | null;
  /** Coverage watermark, not the time a request happened to finish. */
  last_success_at: string | null;
  next_due_at: string;
  consecutive_failures: number;
  status: SourceRunStatus;
}
export interface SourceScheduleStore {
  get(sourceId: string): Promise<SourceScheduleState | undefined>;
  set(state: SourceScheduleState): Promise<void>;
}
export class MemorySourceScheduleStore implements SourceScheduleStore {
  private readonly states = new Map<string, SourceScheduleState>();
  async get(sourceId: string): Promise<SourceScheduleState | undefined> {
    const state = this.states.get(sourceId);
    return state ? { ...state } : undefined;
  }
  async set(state: SourceScheduleState): Promise<void> { this.states.set(state.source_id, { ...state }); }
}
/** The caller owns directory creation and the connection lifetime. */
export class SqliteSourceScheduleStore implements SourceScheduleStore {
  private readonly db: DatabaseSync;
  constructor(filename: string) {
    this.db = new DatabaseSync(filename);
    this.db.exec("PRAGMA busy_timeout = 5000; CREATE TABLE IF NOT EXISTS source_schedule_state (source_id TEXT PRIMARY KEY, state_json TEXT NOT NULL)");
  }
  async get(sourceId: string): Promise<SourceScheduleState | undefined> {
    const row = this.db.prepare("SELECT state_json FROM source_schedule_state WHERE source_id = ?").get(sourceId);
    return row ? JSON.parse(String(row.state_json)) as SourceScheduleState : undefined;
  }
  async set(state: SourceScheduleState): Promise<void> {
    this.db.prepare("INSERT INTO source_schedule_state(source_id,state_json) VALUES (?,?) ON CONFLICT(source_id) DO UPDATE SET state_json=excluded.state_json")
      .run(state.source_id, JSON.stringify(state));
  }
  close(): void { this.db.close(); }
}
