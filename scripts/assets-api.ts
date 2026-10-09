/**
 * 资产线 API（A 线）：/api/v1/assets/*。
 *
 * 路由（挂在 live-intel-server 的只读门禁之前，自带写操作口径）：
 *   GET  /api/v1/assets/overview                      最近扫描摘要 + 未读提醒数 + 最新提醒
 *   GET  /api/v1/assets/repos                         最近一轮仓库列表
 *   GET  /api/v1/assets/components?ecosystem=&q=      组件清单（分页）
 *   GET  /api/v1/assets/alerts?status=new|seen        提醒列表（severity/title 由实时视图富化）
 *   POST /api/v1/assets/scan        {roots?: string[]}   触发一次扫描 + 匹配（仅本机来源）
 *   POST /api/v1/assets/alerts/read {ids?: string[]}     标记已读（空 = 全部）
 *
 * 纪律：扫描只读本地 manifest/git 元信息；匹配只读实时情报视图；两个 POST 都要求
 * localOrigin（本机页面来源），且只写 var/assets.sqlite，不碰情报事件库。
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import nodePath from "node:path";
import { scanLocalProjects } from "../src/assets/src/scanner.js";
import { AssetsStore } from "../src/assets/src/store.js";
import { defaultAssetsDbPath, resolveScanConfig } from "../src/assets/src/config.js";
import { alertsFromMatches } from "../src/assets/src/auto-match.js";
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

  // ── POST /api/v1/assets/scan：扫描 + 匹配 + 落库 ──
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
    const rootsArg = (body as { roots?: unknown }).roots;
    let roots: string[] | undefined;
    if (rootsArg !== undefined) {
      if (!Array.isArray(rootsArg) || rootsArg.length === 0 || rootsArg.length > 20 || !rootsArg.every((r) => typeof r === "string" && r.length > 0 && r.length <= 260)) {
        json(res, 400, { error: { message: "roots must be 1–20 path strings" }, scope: "assets" });
        return true;
      }
      roots = (rootsArg as string[]).map((r) => nodePath.resolve(cwd, r));
    }
    const config = resolveScanConfig(cwd);
    const traceId = "as_" + Date.now().toString(36);
    deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "running", at: new Date().toISOString(), label: "assets.scan_started", details: { reason: "扫描根目录数 " + (roots ?? config.roots).length } });
    const store = new AssetsStore(dbPath);
    try {
      const run = await scanLocalProjects({ roots: roots ?? config.roots, ...config.limits, ...(config.skipDirNames.length > 0 ? { skipDirNames: config.skipDirNames } : {}) });
      const components: MatchedComponent[] = run.repos.flatMap((repo) => repo.components.map((c) => ({ ...c, repo_path: repo.path })));
      let affected = 0;
      let newAlerts = 0;
      if (components.length > 0) {
        const view = await deps.readView();
        const matches = matchComponents(view.intel, components);
        const alerts = alertsFromMatches(matches, run.run_id);
        affected = matches.length;
        store.saveScanRun(run, alerts.length);
        newAlerts = store.insertAlerts(alerts);
      } else {
        store.saveScanRun(run, 0);
      }
      deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "success", at: new Date().toISOString(), label: "assets.scan_finished", details: { artifact_count: run.component_count, reason: "仓库 " + run.repo_count + "；命中 " + affected + "；新增提醒 " + newAlerts } });
      json(res, 200, {
        scope: "assets",
        data_mode: "live",
        run_id: run.run_id,
        status: run.status,
        degraded_to: run.degraded_to,
        note: run.note,
        roots: run.roots,
        repo_count: run.repo_count,
        component_count: run.component_count,
        skipped: run.skipped.length,
        affected,
        new_alerts: newAlerts,
      });
    } catch (error) {
      deps.publishActivity({ trace_id: traceId, intel_id: null, stage: "assets", status: "failed", at: new Date().toISOString(), label: "assets.scan_failed", details: { reason: error instanceof Error ? error.message : String(error) } });
      json(res, 500, { error: { message: error instanceof Error ? error.message : "scan failed" }, scope: "assets" });
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
    const ids = (body as { ids?: unknown }).ids;
    if (ids !== undefined && (!Array.isArray(ids) || !ids.every((x) => typeof x === "string"))) {
      json(res, 400, { error: { message: "ids must be an array of alert_id" }, scope: "assets" });
      return true;
    }
    const store = new AssetsStore(dbPath);
    try {
      const updated = store.markAlertsRead(ids as string[] | undefined);
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
    // ── GET /api/v1/assets/overview ──
    if (path === "/api/v1/assets/overview") {
      const overview = store.overview();
      const alerts = store.listAlerts({ status: "new", limit: 20 });
      json(res, 200, { scope: "assets", data_mode: "live", ...overview, alerts });
      return true;
    }
    // ── GET /api/v1/assets/repos ──
    if (path === "/api/v1/assets/repos") {
      const run = store.latestRun();
      json(res, 200, { scope: "assets", data_mode: "live", run_id: run?.run_id ?? null, repos: store.listRepos() });
      return true;
    }
    // ── GET /api/v1/assets/components ──
    if (path === "/api/v1/assets/components") {
      const ecosystem = url.searchParams.get("ecosystem") ?? undefined;
      const q = url.searchParams.get("q") ?? undefined;
      const limit = Number(url.searchParams.get("limit") ?? "200");
      const offset = Number(url.searchParams.get("offset") ?? "0");
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || !Number.isSafeInteger(offset) || offset < 0) {
        json(res, 400, { error: { message: "invalid limit/offset" }, scope: "assets" });
        return true;
      }
      const result = store.listComponents({ ...(ecosystem ? { ecosystem } : {}), ...(q ? { q } : {}), limit, offset });
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
      const limit = Number(url.searchParams.get("limit") ?? "200");
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
        json(res, 400, { error: { message: "invalid limit" }, scope: "assets" });
        return true;
      }
      const rows = store.listAlerts({ ...(status ? { status } : {}), limit });
      let enriched: AlertRow[] = rows;
      try {
        const view = await deps.readView();
        const byIntelId = new Map(view.intel.map((item) => [item.intel_id, liveIntelItem(view, item)]));
        enriched = rows.map((row) => {
          const live = byIntelId.get(row.intel_id);
          return {
            ...row,
            severity: row.severity ?? live?.severity ?? null,
            title: row.title ?? live?.title ?? null,
          };
        });
      } catch {
        // 视图不可用时提醒仍可读（severity/title 留空），不静默失败：响应带 degraded 标记
        json(res, 200, { scope: "assets", data_mode: "live", alerts: rows, unread_count: store.unreadCount(), degraded_to: "live_view_unavailable" });
        return true;
      }
      json(res, 200, { scope: "assets", data_mode: "live", alerts: enriched, unread_count: store.unreadCount() });
      return true;
    }
    json(res, 404, { error: { message: "unknown assets route" }, scope: "assets" });
    return true;
  } finally {
    store.close();
  }
}
