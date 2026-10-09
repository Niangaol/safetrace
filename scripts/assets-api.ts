/**
 * 资产线 API（A 线）· 多分组版：/api/v1/assets/*。
 *
 * 路由（挂在 live-intel-server 的只读门禁之前，自带写操作口径）：
 *   GET  /api/v1/assets/groups                         分组列表 + 实时统计（未读/仓库/组件/最近扫描）
 *   GET  /api/v1/assets/overview?group_id=             摘要 + 未读提醒数 + 最新提醒（缺省全部组聚合）
 *   GET  /api/v1/assets/repos?group_id=                仓库列表（缺省所有分组最新快照）
 *   GET  /api/v1/assets/components?group_id=&ecosystem=&q=   组件清单（分页）
 *   GET  /api/v1/assets/alerts?group_id=&status=       提醒列表（severity/title 由实时视图富化）
 *   POST /api/v1/assets/groups        {group_id,name,roots,enabled?,note?}  新建/更新分组（localOrigin）
 *   POST /api/v1/assets/groups/delete {group_id}       删除分组定义（历史留痕，localOrigin）
 *   POST /api/v1/assets/scan          {group_id?}      扫描一个/所有启用分组 + 匹配（localOrigin）
 *   POST /api/v1/assets/alerts/read   {ids?} 或 {group_id?}  标记已读（localOrigin）
 *
 * 纪律：扫描只读本地 manifest/git 元信息；匹配只读实时情报视图；所有 POST 都要求
 * localOrigin（本机页面来源），且只写 var/assets.sqlite，不碰情报事件库。
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import nodePath from "node:path";
import { scanLocalProjects } from "../src/assets/src/scanner.js";
import { AssetsStore } from "../src/assets/src/store.js";
import { defaultAssetsDbPath, groupsFromConfig, scanOptionsForGroup } from "../src/assets/src/config.js";
import { alertsFromMatches, readAllIntelItems } from "../src/assets/src/auto-match.js";
import { matchComponents, type MatchedComponent } from "../src/assets/src/matcher.js";
import { liveIntelItem, type LiveKnowledgeView } from "../src/qa/src/live-knowledge-view.js";
import type { AlertRow } from "../src/assets/src/store.js";
import type { ActivityItem } from "./activity-stream.js";

export interface AssetsApiDeps {
  readView: () => Promise<LiveKnowledgeView>;
  publishActivity: (event: Omit<ActivityItem, "event" | "sequence" | "id" | "origin"> & { id?: string; origin?: "live" | "recorded" }) => void;
  localOrigin: (req: IncomingMessage) => boolean;
  cwd?: string;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

async function jsonBody(req: IncomingMessage, maxBytes = 16384): Promise<unknown> {
  if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw new Error("JSON body required");
  let bytes = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const b = Buffer.from(chunk);
    bytes += b.length;
    if (bytes > maxBytes) throw new Error("body exceeds 16KiB");
    chunks.push(b);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

/** 处理 /api/v1/assets/* 请求；返回 true 表示已接管（调用方应直接 return）。 */
export async function handleAssetsRequest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  path: string,
  deps: AssetsApiDeps,
): Promise<boolean> {
  if (!path.startsWith("/api/v1/assets")) return false;
  const cwd = deps.cwd ?? process.cwd();
  const dbPath = defaultAssetsDbPath(cwd);

  // ── POST /api/v1/assets/scan：按组扫描 + 匹配 + 落库 ──
  if (req.method === "POST" && path === "/api/v1/assets/scan") {
    if (!deps.localOrigin(req)) {
      json(res, 403, { error: { message: "local origin required" }, scope: "assets" });
      return true;
    }
    let body: unknown = {};
    try {
      body = await jsonBody(req);
    } catch {
      json(res, 400, { error: { message: "invalid JSON body" }, scope: "assets" });
      return true;
    }
    const groupId = (body as { group_id?: unknown }).group_id;
    if (groupId !== undefined && (typeof groupId !== "string" || (groupId !== "all" && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/.test(groupId)))) {
      json(res, 400, { error: { message: "group_id must be a valid id or 'all'" }, scope: "assets" });
      return true;
    }
    const store = new AssetsStore(dbPath);
    store.seedGroups(groupsFromConfig(cwd));
    const groups = store.listGroups();
    const targets = groupId === undefined || groupId === "all" ? groups.filter((g) => g.enabled) : groups.filter((g) => g.group_id === groupId);
    if (targets.length === 0) {
      store.close();
      json(res, 400, { error: { message: "no matching enabled group" }, scope: "assets" });
      return true;
    }
    const traceId = "as_" + Date.now().toString(36);
    deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "running", at: new Date().toISOString(), label: "assets.scan_started", details: { reason: "分组 " + targets.map((g) => g.group_id).join(",") } });
    try {
      const view = await deps.readView();
      const intelItems = view.intel;
      const results = [];
      for (const group of targets) {
        const run = await scanLocalProjects(scanOptionsForGroup(cwd, group));
        const components: MatchedComponent[] = run.repos.flatMap((repo) => repo.components.map((c) => ({ ...c, repo_path: repo.path, group_id: group.group_id })));
        let affected = 0;
        let newAlerts = 0;
        if (components.length > 0) {
          const matches = matchComponents(intelItems, components);
          affected = matches.length;
          store.saveScanRun(run, matches.length);
          newAlerts = store.insertAlerts(alertsFromMatches(matches, run.run_id));
        } else {
          store.saveScanRun(run, 0);
        }
        results.push({
          group_id: group.group_id,
          run_id: run.run_id,
          status: run.status,
          degraded_to: run.degraded_to,
          note: run.note,
          repo_count: run.repo_count,
          component_count: run.component_count,
          skipped: run.skipped.length,
          affected,
          new_alerts: newAlerts,
        });
      }
      const totalNew = results.reduce((sum, r) => sum + r.new_alerts, 0);
      const totalRepos = results.reduce((sum, r) => sum + r.repo_count, 0);
      const totalComponents = results.reduce((sum, r) => sum + r.component_count, 0);
      deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "success", at: new Date().toISOString(), label: "assets.scan_finished", details: { artifact_count: totalComponents, reason: "分组 " + results.length + " 个；仓库 " + totalRepos + "；新增提醒 " + totalNew } });
      json(res, 200, { scope: "assets", data_mode: "live", groups: results, repo_count: totalRepos, component_count: totalComponents, new_alerts: totalNew, unread_count: store.unreadCount() });
    } catch (error) {
      deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "failed", at: new Date().toISOString(), label: "assets.scan_failed", details: { reason: error instanceof Error ? error.message : String(error) } });
      json(res, 500, { error: { message: error instanceof Error ? error.message : "scan failed" }, scope: "assets" });
    } finally {
      store.close();
    }
    return true;
  }

  // ── POST /api/v1/assets/groups：新建/更新分组 ──
  if (req.method === "POST" && path === "/api/v1/assets/groups") {
    if (!deps.localOrigin(req)) {
      json(res, 403, { error: { message: "local origin required" }, scope: "assets" });
      return true;
    }
    let body: unknown = {};
    try {
      body = await jsonBody(req);
    } catch {
      json(res, 400, { error: { message: "invalid JSON body" }, scope: "assets" });
      return true;
    }
    const rec = body as { group_id?: unknown; name?: unknown; roots?: unknown; enabled?: unknown; note?: unknown };
    const groupId = typeof rec.group_id === "string" ? rec.group_id.trim() : "";
    const name = typeof rec.name === "string" ? rec.name.trim() : "";
    const roots = Array.isArray(rec.roots) ? rec.roots.filter((r): r is string => typeof r === "string" && r.trim() !== "") : [];
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/.test(groupId) || name === "" || roots.length === 0 || roots.length > 20) {
      json(res, 400, { error: { message: "group_id (<=40 字符 id), name 与 1–20 个 roots 必填" }, scope: "assets" });
      return true;
    }
    const store = new AssetsStore(dbPath);
    try {
      const existing = store.getGroup(groupId);
      store.upsertGroup({
        group_id: groupId,
        name,
        roots: roots.map((r) => nodePath.resolve(cwd, r)),
        enabled: rec.enabled === undefined ? true : Boolean(rec.enabled),
        note: typeof rec.note === "string" ? rec.note : null,
        created_at: existing?.created_at ?? new Date().toISOString(),
      });
      json(res, 200, { scope: "assets", action: existing ? "updated" : "created", group: store.getGroup(groupId) });
    } finally {
      store.close();
    }
    return true;
  }

  // ── POST /api/v1/assets/groups/delete：删除分组定义 ──
  if (req.method === "POST" && path === "/api/v1/assets/groups/delete") {
    if (!deps.localOrigin(req)) {
      json(res, 403, { error: { message: "local origin required" }, scope: "assets" });
      return true;
    }
    let body: unknown = {};
    try {
      body = await jsonBody(req);
    } catch {
      json(res, 400, { error: { message: "invalid JSON body" }, scope: "assets" });
      return true;
    }
    const groupId = (body as { group_id?: unknown }).group_id;
    if (typeof groupId !== "string" || groupId === "") {
      json(res, 400, { error: { message: "group_id required" }, scope: "assets" });
      return true;
    }
    const store = new AssetsStore(dbPath);
    try {
      store.deleteGroup(groupId);
      json(res, 200, { scope: "assets", deleted: groupId, groups: store.listGroups() });
    } finally {
      store.close();
    }
    return true;
  }

  // ── POST /api/v1/assets/alerts/read：标记已读 ──
  if (req.method === "POST" && path === "/api/v1/assets/alerts/read") {
    if (!deps.localOrigin(req)) {
      json(res, 403, { error: { message: "local origin required" }, scope: "assets" });
      return true;
    }
    let body: unknown = {};
    try {
      body = await jsonBody(req);
    } catch {
      json(res, 400, { error: { message: "invalid JSON body" }, scope: "assets" });
      return true;
    }
    const rec = body as { ids?: unknown; group_id?: unknown };
    const ids = Array.isArray(rec.ids) && rec.ids.every((x) => typeof x === "string") ? (rec.ids as string[]) : undefined;
    if (rec.ids !== undefined && ids === undefined) {
      json(res, 400, { error: { message: "ids must be an array of alert_id" }, scope: "assets" });
      return true;
    }
    const groupId = typeof rec.group_id === "string" && rec.group_id !== "" ? rec.group_id : undefined;
    const store = new AssetsStore(dbPath);
    try {
      const updated = store.markAlertsRead(ids, groupId);
      json(res, 200, { scope: "assets", updated, unread_count: store.unreadCount() });
    } finally {
      store.close();
    }
    return true;
  }

  if (req.method !== "GET") {
    json(res, 405, { error: { message: "method not allowed on assets API" }, scope: "assets" });
    return true;
  }

  const store = new AssetsStore(dbPath);
  try {
    // ── GET /api/v1/assets/groups：分组 + 统计 ──
    if (path === "/api/v1/assets/groups") {
      json(res, 200, { scope: "assets", data_mode: "live", groups: store.listGroupsWithStats() });
      return true;
    }
    // ── GET /api/v1/assets/overview ──
    if (path === "/api/v1/assets/overview") {
      const groupId = url.searchParams.get("group_id") ?? undefined;
      const overview = store.overview(groupId);
      const alerts = store.listAlerts({ ...(groupId ? { groupId } : {}), status: "new", limit: 20 });
      json(res, 200, { scope: "assets", data_mode: "live", ...overview, alerts });
      return true;
    }
    // ── GET /api/v1/assets/repos ──
    if (path === "/api/v1/assets/repos") {
      const groupId = url.searchParams.get("group_id") ?? undefined;
      const run = store.latestRun(groupId);
      json(res, 200, { scope: "assets", data_mode: "live", group_id: groupId ?? null, run_id: run?.run_id ?? null, repos: store.listRepos(undefined, groupId) });
      return true;
    }
    // ── GET /api/v1/assets/components ──
    if (path === "/api/v1/assets/components") {
      const ecosystem = url.searchParams.get("ecosystem") ?? undefined;
      const q = url.searchParams.get("q") ?? undefined;
      const groupId = url.searchParams.get("group_id") ?? undefined;
      const limit = Number(url.searchParams.get("limit") ?? "200");
      const offset = Number(url.searchParams.get("offset") ?? "0");
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || !Number.isSafeInteger(offset) || offset < 0) {
        json(res, 400, { error: { message: "invalid limit/offset" }, scope: "assets" });
        return true;
      }
      const result = store.listComponents({ ...(groupId ? { groupId } : {}), ...(ecosystem ? { ecosystem } : {}), ...(q ? { q } : {}), limit, offset });
      json(res, 200, { scope: "assets", data_mode: "live", ...result });
      return true;
    }
    // ── GET /api/v1/assets/alerts ──
    if (path === "/api/v1/assets/alerts") {
      const status = url.searchParams.get("status");
      if (status !== null && status !== "new" && status !== "seen") {
        json(res, 400, { error: { message: "status must be new|seen" }, scope: "assets" });
        return true;
      }
      const groupId = url.searchParams.get("group_id") ?? undefined;
      const limit = Number(url.searchParams.get("limit") ?? "200");
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
        json(res, 400, { error: { message: "invalid limit" }, scope: "assets" });
        return true;
      }
      const rows = store.listAlerts({ ...(groupId ? { groupId } : {}), ...(status ? { status } : {}), limit });
      let enriched: AlertRow[] = rows;
      try {
        const view = await deps.readView();
        const byIntelId = new Map(view.intel.map((item) => [item.intel_id, liveIntelItem(view, item)]));
        enriched = rows.map((row) => {
          const live = byIntelId.get(row.intel_id);
          return { ...row, severity: row.severity ?? live?.severity ?? null, title: row.title ?? live?.title ?? null };
        });
      } catch {
        json(res, 200, { scope: "assets", data_mode: "live", alerts: rows, unread_count: store.unreadCount(groupId), degraded_to: "live_view_unavailable" });
        return true;
      }
      json(res, 200, { scope: "assets", data_mode: "live", alerts: enriched, unread_count: store.unreadCount(groupId) });
      return true;
    }
    json(res, 404, { error: { message: "unknown assets route" }, scope: "assets" });
    return true;
  } finally {
    store.close();
  }
}
