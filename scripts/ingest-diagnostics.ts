import { existsSync } from "node:fs";
import { basename, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type SourceFetchState = "live" | "partial" | "fixture" | "no_new_data" | "failed";
export type IngestRunMode = "live" | "mixed" | "fixture" | "no_data";

export interface DiagnosticSource {
  source_id: string;
  state: SourceFetchState;
  raw_docs: number;
  intel_items: number;
  detail: string;
}

export interface DiagnosticFallback {
  trigger: string;
  count: number;
  user_visible: boolean;
}

export interface DiagnosticRun {
  trace_id: string;
  started_at: string;
  last_activity_at: string;
  mode: IngestRunMode;
  sources: DiagnosticSource[];
  counts: {
    raw_docs: number;
    intel_events: number;
    unique_intel_ids: number;
    dq_verdicts: number;
    dq_pass: number;
    dq_degrade: number;
    dq_review: number;
    dq_quarantine: number;
    enrich_items: number;
    enrich_degraded_items: number;
    accepted_items: number;
    enrich_coverage: number | null;
    fallback_events: number;
  };
  fallbacks: DiagnosticFallback[];
  warnings: string[];
}

export interface IngestDiagnostics {
  generated_at: string;
  database_available: boolean;
  database_name: string;
  nvd_api_key_configured: boolean;
  total_runs: number;
  latest_run: DiagnosticRun | null;
  recent_runs: Array<Pick<DiagnosticRun, "trace_id" | "started_at" | "last_activity_at" | "mode" | "counts">>;
  note?: string;
}

type JsonObject = Record<string, unknown>;
function object(value: unknown): JsonObject {
  if (typeof value !== "string") return {};
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as JsonObject : {};
  } catch { return {}; }
}
function text(value: unknown): string { return typeof value === "string" ? value : ""; }

function buildRun(db: DatabaseSync, run: { trace_id: string; started_at: string; last_activity_at: string }): DiagnosticRun {
  const traceId = run.trace_id;
  const fetchRows = db.prepare("SELECT payload FROM lineage_records WHERE trace_id = ? AND stage = 'ingest.fetch' ORDER BY seq").all(traceId) as Array<{ payload: string }>;
  const rawRows = db.prepare("SELECT payload FROM events WHERE trace_id = ? AND topic = 'raw.docs' ORDER BY seq").all(traceId) as Array<{ payload: string }>;
  const intelRows = db.prepare("SELECT payload FROM events WHERE trace_id = ? AND topic = 'intel.items'").all(traceId) as Array<{ payload: string }>;
  const dqRows = db.prepare("SELECT payload FROM events WHERE trace_id = ? AND topic = 'dq.verdicts'").all(traceId) as Array<{ payload: string }>;
  const enrichItems = db.prepare("SELECT COUNT(*) AS n FROM events WHERE trace_id = ? AND topic = 'enrich.items'").get(traceId) as { n: number };
  const degradedF1Rows = db.prepare("SELECT payload FROM lineage_records WHERE trace_id = ? AND stage = 'enrich.f1'").all(traceId) as Array<{ payload: string }>;
  const degradedEnrichIds = new Set(degradedF1Rows.map((row) => object(row.payload)).filter((payload) => payload.status === "degraded").flatMap((payload) => Array.isArray(payload.input_refs) ? (payload.input_refs as JsonObject[]).filter((ref) => ref.kind === "IntelItem").map((ref) => text(ref.id)) : []).filter(Boolean));
  const fallbackRows = db.prepare("SELECT payload FROM events WHERE trace_id = ? AND topic = 'fallback.events'").all(traceId) as Array<{ payload: string }>;

  const rawBySource = new Map<string, string[]>();
  for (const row of rawRows) {
    const payload = object(row.payload);
    const sourceId = text(payload.source_id);
    if (!sourceId) continue;
    const refs = rawBySource.get(sourceId) ?? [];
    refs.push(text(payload.payload_ref));
    rawBySource.set(sourceId, refs);
  }
  const intelBySource = new Map<string, Set<string>>();
  const uniqueIntelIds = new Set<string>();
  for (const row of intelRows) {
    const payload = object(row.payload);
    const intelId = text(payload.intel_id);
    if (intelId) uniqueIntelIds.add(intelId);
    const sourceIds = Array.isArray(payload.source_ids) ? payload.source_ids.filter((x): x is string => typeof x === "string") : [];
    for (const sourceId of sourceIds) {
      const ids = intelBySource.get(sourceId) ?? new Set<string>();
      if (intelId) ids.add(intelId);
      intelBySource.set(sourceId, ids);
    }
  }

  const fallbackCounts = new Map<string, { count: number; visible: boolean }>();
  for (const row of fallbackRows) {
    const payload = object(row.payload);
    const trigger = text(payload.trigger) || "未知降级原因";
    const item = fallbackCounts.get(trigger) ?? { count: 0, visible: true };
    item.count++;
    item.visible = item.visible && payload.user_visible === true;
    fallbackCounts.set(trigger, item);
  }
  const fallbacks = [...fallbackCounts.entries()].map(([trigger, value]) => ({ trigger, count: value.count, user_visible: value.visible })).sort((a, b) => b.count - a.count);

  const sources: DiagnosticSource[] = fetchRows.map((row) => {
    const payload = object(row.payload);
    const operation = text(payload.operation_version);
    const sourceId = operation.endsWith(".fetch.v1") ? operation.slice(0, -".fetch.v1".length) : text(object(payload.source).source_id) || "unknown";
    const decision = typeof payload.decision === "object" && payload.decision !== null ? payload.decision as JsonObject : {};
    const refs = Array.isArray(payload.output_refs) ? payload.output_refs as JsonObject[] : [];
    const hasRaw = refs.some((ref) => ref.kind === "RawDoc");
    const rawRefs = rawBySource.get(sourceId) ?? [];
    const fixtureRaw = rawRefs.some((ref) => ref.includes("fixtures/"));
    const status = text(payload.status);
    let state: SourceFetchState;
    let detail: string;
    if (status === "failed") {
      state = "failed";
      detail = text(payload.error) || "抓取失败（详见 trace）";
    } else if (decision.fallback_to === "partial") {
      state = "partial";
      detail = text(decision.reason) || "部分查询失败，仅展示成功结果";
    } else if (decision.fallback_to === "fixture" || fixtureRaw) {
      state = "fixture";
      detail = text(decision.reason) || "使用了 fixture 回放";
    } else if (!hasRaw) {
      state = "no_new_data";
      detail = text(decision.reason) || "本轮未产生 RawDoc";
    } else {
      state = "live";
      detail = "真实 RawDoc 已落入事件库";
    }
    return { source_id: sourceId, state, raw_docs: rawRefs.length, intel_items: intelBySource.get(sourceId)?.size ?? 0, detail };
  });

  const dq = { pass: 0, degrade: 0, review: 0, quarantine: 0 };
  for (const row of dqRows) {
    const verdict = text(object(row.payload).verdict);
    if (verdict === "pass") dq.pass++;
    else if (verdict === "degrade") dq.degrade++;
    else if (verdict === "review") dq.review++;
    else if (verdict === "quarantine") dq.quarantine++;
  }
  const accepted = dq.pass + dq.degrade;
  const enriched = Number(enrichItems.n);
  const liveSources = sources.filter((source) => source.state === "live").length;
  const fixtureSources = sources.filter((source) => source.state === "fixture").length;
  const partialSources = sources.filter((source) => source.state === "partial").length;
  const failedSources = sources.filter((source) => source.state === "failed").length;
  const mode: IngestRunMode = liveSources === 0
    ? (fixtureSources > 0 && partialSources === 0 && failedSources === 0 ? "fixture" : (partialSources > 0 || failedSources > 0 || fallbackRows.length > 0 ? "mixed" : "no_data"))
    : (fixtureSources > 0 || partialSources > 0 || failedSources > 0 || fallbackRows.length > 0 ? "mixed" : "live");
  const warnings: string[] = [];
  for (const source of sources.filter((item) => item.state === "no_new_data")) warnings.push(source.source_id + "：" + source.detail);
  for (const source of sources.filter((item) => item.state === "partial" || item.state === "fixture" || item.state === "failed")) warnings.push(source.source_id + "：" + source.detail);
  if (degradedEnrichIds.size > 0) warnings.push("已有 " + degradedEnrichIds.size + " 条富化结果的 F1 论文来自 fixture/降级，不应当作实时 arXiv 结果。");
  for (const fallback of fallbacks) warnings.push("降级 " + fallback.count + " 次：" + fallback.trigger + (fallback.user_visible ? "（已向用户标注）" : "（未标注，需排查）"));
  return {
    trace_id: traceId, started_at: run.started_at, last_activity_at: run.last_activity_at, mode, sources,
    counts: {
      raw_docs: rawRows.length, intel_events: intelRows.length, unique_intel_ids: uniqueIntelIds.size,
      dq_verdicts: dqRows.length, dq_pass: dq.pass, dq_degrade: dq.degrade, dq_review: dq.review,
      dq_quarantine: dq.quarantine, enrich_items: enriched, enrich_degraded_items: degradedEnrichIds.size, accepted_items: accepted,
      enrich_coverage: accepted > 0 ? Math.min(1, enriched / accepted) : null, fallback_events: fallbackRows.length,
    },
    fallbacks, warnings,
  };
}

export function summarizeIngestDiagnostics(db: DatabaseSync, databaseName: string, nvdApiKeyConfigured: boolean): IngestDiagnostics {
  const rows = db.prepare("SELECT trace_id, MIN(recorded_at) AS started_at, MAX(recorded_at) AS last_activity_at FROM lineage_records WHERE stage = 'ingest.fetch' GROUP BY trace_id ORDER BY last_activity_at DESC LIMIT 10").all() as Array<{ trace_id: string; started_at: string; last_activity_at: string }>;
  const totalRuns = Number((db.prepare("SELECT COUNT(DISTINCT trace_id) AS n FROM lineage_records WHERE stage='ingest.fetch'").get() as { n: number }).n);
  const runs = rows.map((row) => buildRun(db, row));
  return {
    generated_at: new Date().toISOString(), database_available: true, database_name: databaseName,
    nvd_api_key_configured: nvdApiKeyConfigured, total_runs: totalRuns, latest_run: runs[0] ?? null,
    recent_runs: runs.map(({ trace_id, started_at, last_activity_at, mode, counts }) => ({ trace_id, started_at, last_activity_at, mode, counts })),
    ...(runs.length === 0 ? { note: "SQLite 中还没有 ingest.fetch lineage；尚无可展示的真实采集尝试。" } : {}),
  };
}

export function readIngestDiagnostics(dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite")): IngestDiagnostics {
  const databaseName = basename(dbPath);
  if (!existsSync(dbPath)) return {
    generated_at: new Date().toISOString(), database_available: false, database_name: databaseName,
    nvd_api_key_configured: Boolean(process.env.NVD_API_KEY), total_runs: 0, latest_run: null, recent_runs: [],
    note: "没有找到持久化 SQLite 采集库；当前页面的 fixture 演示不等于真实联网采集。",
  };
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    return summarizeIngestDiagnostics(db, databaseName, Boolean(process.env.NVD_API_KEY));
  } catch (error) {
    return {
      generated_at: new Date().toISOString(), database_available: false, database_name: databaseName,
      nvd_api_key_configured: Boolean(process.env.NVD_API_KEY), total_runs: 0, latest_run: null, recent_runs: [],
      note: "采集库读取失败：" + (error instanceof Error ? error.message : String(error)),
    };
  } finally {
    db?.close();
  }
}
