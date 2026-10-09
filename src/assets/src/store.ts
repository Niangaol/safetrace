/**
 * 资产快照存储：var/assets.sqlite（node:sqlite，零外部依赖）。
 *
 * 与 var/safetrace.sqlite（情报事件库）物理隔离：扫描/告警是资产线数据，
 * 不碰情报库的表与契约。*.sqlite 已被 .gitignore 覆盖，不会进仓库。
 *
 * 分组模型（多文件夹监控）：
 * - groups 表是分组定义的运行时真相源（首次空库由 config/assets-scan.json 播种）；
 * - scan_runs/repos/components/alerts 都带 group_id，按组隔离；
 * - 告警去重键 UNIQUE(group_id, component_key, cve_id)——同一组件同一 CVE
 *   在每个分组各提醒一次；重复扫描/重复匹配 INSERT OR IGNORE 自然幂等。
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { AssetGroup, Ecosystem, NewAssetAlert, RepoSnapshot, ScanRun } from "./types.js";

const SCHEMA_SQL = [
  "CREATE TABLE IF NOT EXISTS groups (",
  "  group_id TEXT PRIMARY KEY,",
  "  name TEXT NOT NULL,",
  "  roots TEXT NOT NULL,",
  "  enabled INTEGER NOT NULL,",
  "  note TEXT,",
  "  created_at TEXT NOT NULL",
  ")",
  "CREATE TABLE IF NOT EXISTS scan_runs (",
  "  run_id TEXT PRIMARY KEY,",
  "  group_id TEXT NOT NULL DEFAULT 'adhoc',",
  "  group_name TEXT NOT NULL DEFAULT '临时扫描',",
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
  "CREATE INDEX IF NOT EXISTS idx_scan_runs_group ON scan_runs(group_id, finished_at)",
  "CREATE TABLE IF NOT EXISTS repos (",
  "  repo_id TEXT PRIMARY KEY,",
  "  run_id TEXT NOT NULL,",
  "  group_id TEXT NOT NULL DEFAULT 'adhoc',",
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
  "CREATE INDEX IF NOT EXISTS idx_repos_group ON repos(group_id)",
  "CREATE TABLE IF NOT EXISTS components (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  run_id TEXT NOT NULL,",
  "  repo_id TEXT NOT NULL,",
  "  repo_path TEXT NOT NULL,",
  "  group_id TEXT NOT NULL DEFAULT 'adhoc',",
  "  ecosystem TEXT NOT NULL,",
  "  name TEXT NOT NULL,",
  "  version TEXT NOT NULL,",
  "  constraint_raw TEXT NOT NULL,",
  "  version_is_range_floor INTEGER NOT NULL,",
  "  source_file TEXT NOT NULL",
  ")",
  "CREATE INDEX IF NOT EXISTS idx_components_run ON components(run_id)",
  "CREATE INDEX IF NOT EXISTS idx_components_group ON components(group_id)",
  "CREATE INDEX IF NOT EXISTS idx_components_key ON components(ecosystem, name)",
  "CREATE TABLE IF NOT EXISTS alerts (",
  "  alert_id TEXT PRIMARY KEY,",
  "  created_at TEXT NOT NULL,",
  "  component_key TEXT NOT NULL,",
  "  ecosystem TEXT NOT NULL,",
  "  name TEXT NOT NULL,",
  "  version TEXT NOT NULL,",
  "  repo_path TEXT NOT NULL,",
  "  group_id TEXT NOT NULL DEFAULT 'adhoc',",
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
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(group_id, component_key, cve_id)",
  "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)",
  "CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(group_id, status)",
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
  group_id: string;
  group_name: string;
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
  group_id: string;
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
  group_id: string;
}

export interface AlertRow {
  alert_id: string;
  created_at: string;
  component_key: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  repo_path: string;
  group_id: string;
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

export interface GroupRow extends AssetGroup {}

/** 分组 + 其实时统计（供分组管理 UI）。 */
export interface GroupStatsRow extends AssetGroup {
  last_finished_at: string | null;
  repo_count: number;
  component_count: number;
  unread_count: number;
  alert_count: number;
}

export interface AssetsOverview {
  /** group_id 为空 = 全部组聚合。 */
  group_id: string | null;
  group_name: string | null;
  last_run: RunRow | null;
  repo_count: number;
  component_count: number;
  alert_count: number;
  unread_count: number;
  by_ecosystem: Record<string, number>;
  by_group: Array<{ group_id: string; group_name: string; repo_count: number; component_count: number; unread_count: number; last_finished_at: string | null }>;
}

export class AssetsStore {
  readonly dbPath: string;
  private readonly db: DatabaseSync;

  constructor(dbPath: string = "var/assets.sqlite") {
    this.dbPath = resolve(dbPath);
    mkdirSync(dirname(this.dbPath), { recursive: true }); // node:sqlite 不建父目录
    this.db = new DatabaseSync(this.dbPath);
    // 先迁移旧库（补 group_id 列/重建去重索引），再执行建表语句：
    // 否则 SCHEMA 里引用 group_id 的 CREATE INDEX 会在旧库上报 "no such column"。
    this.migrateLegacy();
    this.db.exec(SCHEMA_SQL);
  }

  /** 旧库（分组模型上线前）迁移：补 group_id 列 + 重建去重索引。只做追加，不丢数据。 */
  private migrateLegacy(): void {
    const columns = (table: string): string[] =>
      (this.db.prepare("PRAGMA table_info(" + table + ")").all() as Array<{ name: string }>).map((r) => r.name);
    const tableExists = (table: string): boolean =>
      this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table) !== undefined;
    if (tableExists("scan_runs") && !columns("scan_runs").includes("group_id")) {
      this.db.exec("ALTER TABLE scan_runs ADD COLUMN group_id TEXT NOT NULL DEFAULT 'adhoc'");
      this.db.exec("ALTER TABLE scan_runs ADD COLUMN group_name TEXT NOT NULL DEFAULT '临时扫描'");
      this.db.exec("CREATE INDEX IF NOT EXISTS idx_scan_runs_group ON scan_runs(group_id, finished_at)");
    }
    for (const table of ["repos", "components", "alerts"]) {
      if (tableExists(table) && !columns(table).includes("group_id")) {
        this.db.exec("ALTER TABLE " + table + " ADD COLUMN group_id TEXT NOT NULL DEFAULT 'adhoc'");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_" + table + "_group ON " + table + "(group_id)");
      }
    }
    // 去重索引从 (component_key, cve_id) 升级为 (group_id, component_key, cve_id)
    if (tableExists("alerts")) {
      const indexColumns = this.db.prepare("PRAGMA index_info(idx_alerts_dedupe)").all() as Array<{ name: string }>;
      if (indexColumns.length > 0 && !indexColumns.some((c) => c.name === "group_id")) {
        this.db.exec("DROP INDEX idx_alerts_dedupe");
        this.db.exec("CREATE UNIQUE INDEX idx_alerts_dedupe ON alerts(group_id, component_key, cve_id)");
      }
    }
  }

  // ── 分组管理 ──

  listGroups(): GroupRow[] {
    const rows = this.db.prepare("SELECT * FROM groups ORDER BY created_at, group_id").all() as Array<Record<string, unknown>>;
    return rows.map(toGroupRow);
  }

  getGroup(groupId: string): GroupRow | null {
    const row = this.db.prepare("SELECT * FROM groups WHERE group_id = ?").get(groupId) as Record<string, unknown> | undefined;
    return row ? toGroupRow(row) : null;
  }

  upsertGroup(group: AssetGroup): void {
    this.db
      .prepare(
        "INSERT INTO groups (group_id, name, roots, enabled, note, created_at) VALUES (?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(group_id) DO UPDATE SET name=excluded.name, roots=excluded.roots, enabled=excluded.enabled, note=excluded.note",
      )
      .run(group.group_id, group.name, JSON.stringify(group.roots), group.enabled ? 1 : 0, group.note, group.created_at);
  }

  deleteGroup(groupId: string): void {
    // 只删分组定义；历史 runs/components/alerts 保留（group_id 仍在，可追溯）
    this.db.prepare("DELETE FROM groups WHERE group_id = ?").run(groupId);
  }

  /** 空库时播种配置里的分组；返回实际播种条数。 */
  seedGroups(groups: readonly AssetGroup[]): number {
    const existing = (this.db.prepare("SELECT COUNT(*) AS n FROM groups").get() as { n: number }).n;
    if (existing > 0 || groups.length === 0) return 0;
    for (const group of groups) this.upsertGroup(group);
    return groups.length;
  }

  /** 分组 + 实时统计（分组管理 UI 一行一个）。 */
  listGroupsWithStats(): GroupStatsRow[] {
    const runs = this.latestRunPerGroup();
    const runByGroup = new Map(runs.map((r) => [r.group_id, r]));
    return this.listGroups().map((group) => {
      const run = runByGroup.get(group.group_id) ?? null;
      return {
        ...group,
        last_finished_at: run?.finished_at ?? null,
        repo_count: run?.repo_count ?? 0,
        component_count: run?.component_count ?? 0,
        alert_count: (this.db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE group_id = ?").get(group.group_id) as { n: number }).n,
        unread_count: this.unreadCount(group.group_id),
      };
    });
  }

  // ── 扫描轮次 ──

  /** 一次扫描轮次整体落库（事务：run + repos + components）。 */
  saveScanRun(run: ScanRun, alertCount: number): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          "INSERT OR REPLACE INTO scan_runs (run_id, group_id, group_name, started_at, finished_at, roots, status, degraded_to, note, repo_count, component_count, alert_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(run.run_id, run.group_id, run.group_name, run.started_at, run.finished_at, JSON.stringify(run.roots), run.status, run.degraded_to, run.note, run.repo_count, run.component_count, alertCount);
      for (const repo of run.repos) this.saveRepo(run.run_id, run.group_id, repo);
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

  private saveRepo(runId: string, groupId: string, repo: RepoSnapshot): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO repos (repo_id, run_id, group_id, path, remote_url, branch, head_commit, head_commit_at, is_git, git_note, languages, frameworks, manifests, component_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        repo.repo_id, runId, groupId, repo.path, repo.remote_url, repo.branch, repo.head_commit, repo.head_commit_at,
        repo.is_git ? 1 : 0, repo.git_note,
        JSON.stringify(repo.languages), JSON.stringify(repo.frameworks), JSON.stringify(repo.manifests),
        repo.components.length,
      );
    const insert = this.db.prepare(
      "INSERT INTO components (run_id, repo_id, repo_path, group_id, ecosystem, name, version, constraint_raw, version_is_range_floor, source_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const c of repo.components) {
      insert.run(runId, repo.repo_id, repo.path, groupId, c.ecosystem, c.name, c.version, c.constraint_raw, c.version_is_range_floor ? 1 : 0, c.source_file);
    }
  }

  /** 最近一轮扫描；groupId 缺省 = 全局最近一轮。 */
  latestRun(groupId?: string): RunRow | null {
    const row = (groupId === undefined
      ? this.db.prepare("SELECT * FROM scan_runs ORDER BY finished_at DESC, rowid DESC LIMIT 1").get()
      : this.db.prepare("SELECT * FROM scan_runs WHERE group_id = ? ORDER BY finished_at DESC, rowid DESC LIMIT 1").get(groupId)
    ) as Record<string, unknown> | undefined;
    return row ? toRunRow(row) : null;
  }

  /** 每个分组各自最近的一轮扫描（按 finished_at 倒序取首条）。 */
  latestRunPerGroup(): RunRow[] {
    const rows = this.db.prepare("SELECT * FROM scan_runs ORDER BY finished_at DESC, rowid DESC").all() as Array<Record<string, unknown>>;
    const seen = new Set<string>();
    const out: RunRow[] = [];
    for (const row of rows) {
      const run = toRunRow(row);
      if (seen.has(run.group_id)) continue;
      seen.add(run.group_id);
      out.push(run);
    }
    return out;
  }

  /** 指定分组（缺省 = 所有有扫描记录的分组）最新一轮的 run_id 集合。 */
  private latestRunIds(groupId?: string): string[] {
    const runs = this.latestRunPerGroup().filter((r) => groupId === undefined || r.group_id === groupId);
    return runs.map((r) => r.run_id);
  }

  listRepos(runId?: string, groupId?: string): RepoRow[] {
    if (runId !== undefined) {
      const rows = this.db.prepare("SELECT * FROM repos WHERE run_id = ? ORDER BY path").all(runId) as Array<Record<string, unknown>>;
      return rows.map(toRepoRow);
    }
    const runIds = this.latestRunIds(groupId);
    if (runIds.length === 0) return [];
    const placeholders = runIds.map(() => "?").join(",");
    const rows = this.db
      .prepare("SELECT * FROM repos WHERE run_id IN (" + placeholders + ") ORDER BY path")
      .all(...runIds) as Array<Record<string, unknown>>;
    return rows.map(toRepoRow);
  }

  /** 最新一轮的组件（匹配器输入）。groupId 缺省 = 所有分组。 */
  latestComponents(groupId?: string): ComponentRow[] {
    const runIds = this.latestRunIds(groupId);
    if (runIds.length === 0) return [];
    const placeholders = runIds.map(() => "?").join(",");
    const rows = this.db
      .prepare("SELECT * FROM components WHERE run_id IN (" + placeholders + ") ORDER BY id")
      .all(...runIds) as Array<Record<string, unknown>>;
    return rows.map(toComponentRow);
  }

  listComponents(options: { groupId?: string; ecosystem?: string; q?: string; limit?: number; offset?: number } = {}): { total: number; rows: ComponentRow[] } {
    const runIds = this.latestRunIds(options.groupId);
    if (runIds.length === 0) return { total: 0, rows: [] };
    const where: string[] = ["run_id IN (" + runIds.map(() => "?").join(",") + ")"];
    const params: SQLInputValue[] = [...runIds];
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

  /** 插入告警（按 group_id+component_key+cve_id 去重）；返回实际新增条数。 */
  insertAlerts(alerts: readonly NewAssetAlert[], now: () => Date = () => new Date()): number {
    if (alerts.length === 0) return 0;
    const createdAt = now().toISOString();
    const insert = this.db.prepare(
      "INSERT OR IGNORE INTO alerts (alert_id, created_at, component_key, ecosystem, name, version, repo_path, group_id, cve_id, intel_id, severity, title, matched_rule, matched_ranges, reason, vendor_unverified, status, seen_at, first_run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, 'new', NULL, ?)",
    );
    let inserted = 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const alert of alerts) {
        const result = insert.run(
          "al_" + createdAt.replace(/[^0-9]/g, "") + "_" + Math.random().toString(36).slice(2, 8),
          createdAt, alert.component_key, alert.ecosystem, alert.name, alert.version, alert.repo_path, alert.group_id,
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

  listAlerts(options: { groupId?: string; status?: "new" | "seen"; limit?: number } = {}): AlertRow[] {
    const where: string[] = [];
    const params: SQLInputValue[] = [];
    if (options.groupId !== undefined) {
      where.push("group_id = ?");
      params.push(options.groupId);
    }
    if (options.status) {
      where.push("status = ?");
      params.push(options.status);
    }
    const whereSql = where.length > 0 ? "WHERE " + where.join(" AND ") : "";
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 1000);
    const rows = this.db
      .prepare("SELECT * FROM alerts " + whereSql + " ORDER BY created_at DESC LIMIT ?")
      .all(...params, limit) as Array<Record<string, unknown>>;
    return rows.map(toAlertRow);
  }

  /** 标记已读；ids 为空 = 该分组（或缺省全部）的未读全标。返回更新条数。 */
  markAlertsRead(ids?: readonly string[], groupId?: string, now: () => Date = () => new Date()): number {
    const seenAt = now().toISOString();
    if (ids && ids.length > 0) {
      const placeholders = ids.map(() => "?").join(",");
      const result = this.db
        .prepare("UPDATE alerts SET status = 'seen', seen_at = ? WHERE alert_id IN (" + placeholders + ") AND status = 'new'")
        .run(seenAt, ...ids);
      return Number(result.changes);
    }
    const result = groupId === undefined
      ? this.db.prepare("UPDATE alerts SET status = 'seen', seen_at = ? WHERE status = 'new'").run(seenAt)
      : this.db.prepare("UPDATE alerts SET status = 'seen', seen_at = ? WHERE status = 'new' AND group_id = ?").run(seenAt, groupId);
    return Number(result.changes);
  }

  unreadCount(groupId?: string): number {
    const row = (groupId === undefined
      ? this.db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE status = 'new'").get()
      : this.db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE status = 'new' AND group_id = ?").get(groupId)
    ) as { n: number };
    return row.n;
  }

  /** 概览：groupId 缺省 = 全部组聚合。 */
  overview(groupId?: string): AssetsOverview {
    const lastRun = this.latestRun(groupId);
    const runs = this.latestRunPerGroup().filter((r) => groupId === undefined || r.group_id === groupId);
    const runIds = runs.map((r) => r.run_id);
    const byEcosystem: Record<string, number> = {};
    if (runIds.length > 0) {
      const placeholders = runIds.map(() => "?").join(",");
      const ecosystemRows = this.db
        .prepare("SELECT ecosystem, COUNT(*) AS n FROM components WHERE run_id IN (" + placeholders + ") GROUP BY ecosystem")
        .all(...runIds) as Array<{ ecosystem: string; n: number }>;
      for (const row of ecosystemRows) byEcosystem[row.ecosystem] = row.n;
    }
    const alertScope = groupId === undefined ? "" : "WHERE group_id = ?";
    const alertParams: SQLInputValue[] = groupId === undefined ? [] : [groupId];
    return {
      group_id: groupId ?? null,
      group_name: lastRun?.group_name ?? null,
      last_run: lastRun,
      repo_count: runs.reduce((sum, r) => sum + r.repo_count, 0),
      component_count: runs.reduce((sum, r) => sum + r.component_count, 0),
      alert_count: (this.db.prepare("SELECT COUNT(*) AS n FROM alerts " + alertScope).get(...alertParams) as { n: number }).n,
      unread_count: this.unreadCount(groupId),
      by_ecosystem: byEcosystem,
      by_group: runs.map((r) => ({
        group_id: r.group_id,
        group_name: r.group_name,
        repo_count: r.repo_count,
        component_count: r.component_count,
        unread_count: this.unreadCount(r.group_id),
        last_finished_at: r.finished_at,
      })),
    };
  }

  close(): void {
    this.db.close();
  }
}

function toRunRow(row: Record<string, unknown>): RunRow {
  return {
    run_id: String(row.run_id),
    group_id: String(row.group_id ?? "adhoc"),
    group_name: String(row.group_name ?? "临时扫描"),
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

function toGroupRow(row: Record<string, unknown>): GroupRow {
  return {
    group_id: String(row.group_id),
    name: String(row.name),
    roots: JSON.parse(String(row.roots)) as string[],
    enabled: Boolean(row.enabled),
    note: row.note === null ? null : String(row.note),
    created_at: String(row.created_at),
  };
}

function toRepoRow(row: Record<string, unknown>): RepoRow {
  return {
    repo_id: String(row.repo_id),
    run_id: String(row.run_id),
    group_id: String(row.group_id ?? "adhoc"),
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
    group_id: String(row.group_id ?? "adhoc"),
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
    group_id: String(row.group_id ?? "adhoc"),
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
