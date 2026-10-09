/**
 * 资产快照存储：var/assets.sqlite（node:sqlite，零外部依赖）。
 *
 * 与 var/safetrace.sqlite（情报事件库）物理隔离：扫描/告警是资产线数据，
 * 不碰情报库的表与契约。*.sqlite 已被 .gitignore 覆盖，不会进仓库。
 *
 * 告警去重：UNIQUE(component_key, cve_id)——同一组件的同一 CVE 只提醒一次，
 * 重复扫描/重复匹配通过 INSERT OR IGNORE 自然幂等；已读后再次命中不复活。
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { Ecosystem, NewAssetAlert, RepoSnapshot, ScanRun } from "./types.js";

const SCHEMA_SQL = [
  "CREATE TABLE IF NOT EXISTS scan_runs (",
  "  run_id TEXT PRIMARY KEY,",
  "  started_at TEXT NOT NULL,",
  "  finished_at TEXT NOT NULL,",
  "  roots TEXT NOT NULL,",
  "  status TEXT NOT NULL,",
  "  degraded_to TEXT,",
  "  note TEXT,",
  "  repo_count INTEGER NOT NULL,",
  "  component_count INTEGER NOT NULL,",
  "  alert_count INTEGER NOT NULL",
  ")",
  "CREATE TABLE IF NOT EXISTS repos (",
  "  repo_id TEXT PRIMARY KEY,",
  "  run_id TEXT NOT NULL,",
  "  path TEXT NOT NULL,",
  "  remote_url TEXT,",
  "  branch TEXT,",
  "  head_commit TEXT,",
  "  head_commit_at TEXT,",
  "  is_git INTEGER NOT NULL,",
  "  git_note TEXT,",
  "  languages TEXT NOT NULL,",
  "  frameworks TEXT NOT NULL,",
  "  manifests TEXT NOT NULL,",
  "  component_count INTEGER NOT NULL",
  ")",
  "CREATE INDEX IF NOT EXISTS idx_repos_run ON repos(run_id)",
  "CREATE TABLE IF NOT EXISTS components (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  run_id TEXT NOT NULL,",
  "  repo_id TEXT NOT NULL,",
  "  repo_path TEXT NOT NULL,",
  "  ecosystem TEXT NOT NULL,",
  "  name TEXT NOT NULL,",
  "  version TEXT NOT NULL,",
  "  constraint_raw TEXT NOT NULL,",
  "  version_is_range_floor INTEGER NOT NULL,",
  "  source_file TEXT NOT NULL",
  ")",
  "CREATE INDEX IF NOT EXISTS idx_components_run ON components(run_id)",
  "CREATE INDEX IF NOT EXISTS idx_components_key ON components(ecosystem, name)",
  "CREATE TABLE IF NOT EXISTS alerts (",
  "  alert_id TEXT PRIMARY KEY,",
  "  created_at TEXT NOT NULL,",
  "  component_key TEXT NOT NULL,",
  "  ecosystem TEXT NOT NULL,",
  "  name TEXT NOT NULL,",
  "  version TEXT NOT NULL,",
  "  repo_path TEXT NOT NULL,",
  "  cve_id TEXT NOT NULL,",
  "  intel_id TEXT NOT NULL,",
  "  severity TEXT,",
  "  title TEXT,",
  "  matched_rule TEXT NOT NULL,",
  "  matched_ranges TEXT NOT NULL,",
  "  reason TEXT NOT NULL,",
  "  vendor_unverified INTEGER NOT NULL,",
  "  status TEXT NOT NULL,",
  "  seen_at TEXT,",
  "  first_run_id TEXT NOT NULL",
  ")",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(component_key, cve_id)",
  "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)",
  "CREATE TABLE IF NOT EXISTS meta (",
  "  key TEXT PRIMARY KEY,",
  "  value TEXT NOT NULL",
  ")",
]
  // node:sqlite 的 exec 执行多条语句时要求分号分隔：以 ")" 收尾的行是完整语句（表闭合/CREATE INDEX）
  .map((line) => (line.endsWith(")") ? line + ";" : line))
  .join("\n");

export interface RunRow {
  run_id: string;
  started_at: string;
  finished_at: string;
  roots: string[];
  status: string;
  degraded_to: string | null;
  note: string | null;
  repo_count: number;
  component_count: number;
  alert_count: number;
}

export interface RepoRow {
  repo_id: string;
  run_id: string;
  path: string;
  remote_url: string | null;
  branch: string | null;
  head_commit: string | null;
  head_commit_at: string | null;
  is_git: boolean;
  git_note: string | null;
  languages: string[];
  frameworks: string[];
  manifests: string[];
  component_count: number;
}

export interface ComponentRow {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  constraint_raw: string;
  version_is_range_floor: boolean;
  source_file: string;
  repo_path: string;
}

export interface AlertRow {
  alert_id: string;
  created_at: string;
  component_key: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  repo_path: string;
  cve_id: string;
  intel_id: string;
  severity: string | null;
  title: string | null;
  matched_rule: string;
  matched_ranges: string[];
  reason: string;
  vendor_unverified: boolean;
  status: "new" | "seen";
  seen_at: string | null;
  first_run_id: string;
}

export interface AssetsOverview {
  last_run: RunRow | null;
  repo_count: number;
  component_count: number;
  alert_count: number;
  unread_count: number;
  by_ecosystem: Record<string, number>;
}

export class AssetsStore {
  readonly dbPath: string;
  private readonly db: DatabaseSync;

  constructor(dbPath: string = "var/assets.sqlite") {
    this.dbPath = resolve(dbPath);
    mkdirSync(dirname(this.dbPath), { recursive: true }); // node:sqlite 不建父目录
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec(SCHEMA_SQL);
  }

  /** 一次扫描轮次整体落库（事务：run + repos + components）。 */
  saveScanRun(run: ScanRun, alertCount: number): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT OR REPLACE INTO scan_runs (run_id, started_at, finished_at, roots, status, degraded_to, note, repo_count, component_count, alert_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(run.run_id, run.started_at, run.finished_at, JSON.stringify(run.roots), run.status, run.degraded_to, run.note, run.repo_count, run.component_count, alertCount);
      for (const repo of run.repos) this.saveRepo(run.run_id, repo);
      this.db.exec("COMMIT");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* 事务可能已关闭 */
      }
      throw error;
    }
  }

  private saveRepo(runId: string, repo: RepoSnapshot): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO repos (repo_id, run_id, path, remote_url, branch, head_commit, head_commit_at, is_git, git_note, languages, frameworks, manifests, component_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        repo.repo_id, runId, repo.path, repo.remote_url, repo.branch, repo.head_commit, repo.head_commit_at,
        repo.is_git ? 1 : 0, repo.git_note,
        JSON.stringify(repo.languages), JSON.stringify(repo.frameworks), JSON.stringify(repo.manifests),
        repo.components.length,
      );
    const insert = this.db.prepare(
      "INSERT INTO components (run_id, repo_id, repo_path, ecosystem, name, version, constraint_raw, version_is_range_floor, source_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const c of repo.components) {
      insert.run(runId, repo.repo_id, repo.path, c.ecosystem, c.name, c.version, c.constraint_raw, c.version_is_range_floor ? 1 : 0, c.source_file);
    }
  }

  latestRun(): RunRow | null {
    const row = this.db
      .prepare("SELECT * FROM scan_runs ORDER BY finished_at DESC, rowid DESC LIMIT 1")
      .get() as Record<string, unknown> | undefined;
    return row ? toRunRow(row) : null;
  }

  listRepos(runId?: string): RepoRow[] {
    const target = runId ?? this.latestRun()?.run_id;
    if (!target) return [];
    const rows = this.db.prepare("SELECT * FROM repos WHERE run_id = ? ORDER BY path").all(target) as Array<Record<string, unknown>>;
    return rows.map(toRepoRow);
  }

  /** 最新一轮的组件（匹配器输入）。 */
  latestComponents(): ComponentRow[] {
    const target = this.latestRun()?.run_id;
    if (!target) return [];
    const rows = this.db.prepare("SELECT * FROM components WHERE run_id = ? ORDER BY id").all(target) as Array<Record<string, unknown>>;
    return rows.map(toComponentRow);
  }

  listComponents(options: { ecosystem?: string; q?: string; limit?: number; offset?: number } = {}): { total: number; rows: ComponentRow[] } {
    const runId = this.latestRun()?.run_id;
    if (!runId) return { total: 0, rows: [] };
    const where: string[] = ["run_id = ?"];
    const params: SQLInputValue[] = [runId];
    if (options.ecosystem) {
      where.push("ecosystem = ?");
      params.push(options.ecosystem);
    }
    if (options.q && options.q.trim()) {
      where.push("(LOWER(name) LIKE ? OR LOWER(repo_path) LIKE ?)");
      const needle = "%" + options.q.trim().toLowerCase() + "%";
      params.push(needle, needle);
    }
    const whereSql = "WHERE " + where.join(" AND ");
    const total = (this.db.prepare("SELECT COUNT(*) AS n FROM components " + whereSql).get(...params) as { n: number }).n;
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 1000);
    const offset = Math.max(options.offset ?? 0, 0);
    const rows = this.db
      .prepare("SELECT * FROM components " + whereSql + " ORDER BY ecosystem, name LIMIT ? OFFSET ?")
      .all(...params, limit, offset) as Array<Record<string, unknown>>;
    return { total, rows: rows.map(toComponentRow) };
  }

  /** 插入告警（按 component_key+cve_id 去重）；返回实际新增条数。 */
  insertAlerts(alerts: readonly NewAssetAlert[], now: () => Date = () => new Date()): number {
    if (alerts.length === 0) return 0;
    const createdAt = now().toISOString();
    const insert = this.db.prepare(
      "INSERT OR IGNORE INTO alerts (alert_id, created_at, component_key, ecosystem, name, version, repo_path, cve_id, intel_id, severity, title, matched_rule, matched_ranges, reason, vendor_unverified, status, seen_at, first_run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, 'new', NULL, ?)",
    );
    let inserted = 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const alert of alerts) {
        const result = insert.run(
          "al_" + createdAt.replace(/[^0-9]/g, "") + "_" + Math.random().toString(36).slice(2, 8),
          createdAt, alert.component_key, alert.ecosystem, alert.name, alert.version, alert.repo_path,
          alert.cve_id, alert.intel_id, alert.matched_rule, JSON.stringify(alert.matched_ranges),
          alert.reason, alert.vendor_unverified ? 1 : 0, alert.first_run_id,
        );
        if (result.changes > 0) inserted += 1;
      }
      this.db.exec("COMMIT");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* 事务可能已关闭 */
      }
      throw error;
    }
    return inserted;
  }

  listAlerts(options: { status?: "new" | "seen"; limit?: number } = {}): AlertRow[] {
    const where = options.status ? "WHERE status = ?" : "";
    const params: SQLInputValue[] = options.status ? [options.status] : [];
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 1000);
    const rows = this.db
      .prepare("SELECT * FROM alerts " + where + " ORDER BY created_at DESC LIMIT ?")
      .all(...params, limit) as Array<Record<string, unknown>>;
    return rows.map(toAlertRow);
  }

  /** 标记已读；ids 为空 = 全部已读。返回更新条数。 */
  markAlertsRead(ids?: readonly string[], now: () => Date = () => new Date()): number {
    const seenAt = now().toISOString();
    if (ids && ids.length > 0) {
      const placeholders = ids.map(() => "?").join(",");
      const result = this.db
        .prepare("UPDATE alerts SET status = 'seen', seen_at = ? WHERE alert_id IN (" + placeholders + ") AND status = 'new'")
        .run(seenAt, ...ids);
      return Number(result.changes);
    }
    const result = this.db.prepare("UPDATE alerts SET status = 'seen', seen_at = ? WHERE status = 'new'").run(seenAt);
    return Number(result.changes);
  }

  unreadCount(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE status = 'new'").get() as { n: number };
    return row.n;
  }

  overview(): AssetsOverview {
    const lastRun = this.latestRun();
    const ecosystemRows = this.db
      .prepare("SELECT ecosystem, COUNT(*) AS n FROM components " + (lastRun ? "WHERE run_id = ?" : "") + " GROUP BY ecosystem")
      .all(...(lastRun ? [lastRun.run_id] : [])) as Array<{ ecosystem: string; n: number }>;
    const byEcosystem: Record<string, number> = {};
    for (const row of ecosystemRows) byEcosystem[row.ecosystem] = row.n;
    return {
      last_run: lastRun,
      repo_count: lastRun?.repo_count ?? 0,
      component_count: lastRun?.component_count ?? 0,
      alert_count: (this.db.prepare("SELECT COUNT(*) AS n FROM alerts").get() as { n: number }).n,
      unread_count: this.unreadCount(),
      by_ecosystem: byEcosystem,
    };
  }

  close(): void {
    this.db.close();
  }
}

function toRunRow(row: Record<string, unknown>): RunRow {
  return {
    run_id: String(row.run_id),
    started_at: String(row.started_at),
    finished_at: String(row.finished_at),
    roots: JSON.parse(String(row.roots)) as string[],
    status: String(row.status),
    degraded_to: row.degraded_to === null ? null : String(row.degraded_to),
    note: row.note === null ? null : String(row.note),
    repo_count: Number(row.repo_count),
    component_count: Number(row.component_count),
    alert_count: Number(row.alert_count),
  };
}

function toRepoRow(row: Record<string, unknown>): RepoRow {
  return {
    repo_id: String(row.repo_id),
    run_id: String(row.run_id),
    path: String(row.path),
    remote_url: row.remote_url === null ? null : String(row.remote_url),
    branch: row.branch === null ? null : String(row.branch),
    head_commit: row.head_commit === null ? null : String(row.head_commit),
    head_commit_at: row.head_commit_at === null ? null : String(row.head_commit_at),
    is_git: Boolean(row.is_git),
    git_note: row.git_note === null ? null : String(row.git_note),
    languages: JSON.parse(String(row.languages)) as string[],
    frameworks: JSON.parse(String(row.frameworks)) as string[],
    manifests: JSON.parse(String(row.manifests)) as string[],
    component_count: Number(row.component_count),
  };
}

function toComponentRow(row: Record<string, unknown>): ComponentRow {
  return {
    ecosystem: row.ecosystem as Ecosystem,
    name: String(row.name),
    version: String(row.version),
    constraint_raw: String(row.constraint_raw),
    version_is_range_floor: Boolean(row.version_is_range_floor),
    source_file: String(row.source_file),
    repo_path: String(row.repo_path),
  };
}

function toAlertRow(row: Record<string, unknown>): AlertRow {
  return {
    alert_id: String(row.alert_id),
    created_at: String(row.created_at),
    component_key: String(row.component_key),
    ecosystem: row.ecosystem as Ecosystem,
    name: String(row.name),
    version: String(row.version),
    repo_path: String(row.repo_path),
    cve_id: String(row.cve_id),
    intel_id: String(row.intel_id),
    severity: row.severity === null ? null : String(row.severity),
    title: row.title === null ? null : String(row.title),
    matched_rule: String(row.matched_rule),
    matched_ranges: JSON.parse(String(row.matched_ranges)) as string[],
    reason: String(row.reason),
    vendor_unverified: Boolean(row.vendor_unverified),
    status: String(row.status) as "new" | "seen",
    seen_at: row.seen_at === null ? null : String(row.seen_at),
    first_run_id: String(row.first_run_id),
  };
}
