/**
 * 本机可操作演示 API：采集与索引输入为仓库 fixture；Q4 在 StepPlan 已配置时调用外部模型，失败回退原模板。
 * 只监听 127.0.0.1；没有真实资产或联网采集，fixture 状态始终显式。
 */
import { createServer, type Server, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { readIngestDiagnostics } from "./ingest-diagnostics.js";
import { EventBus, MemoryEventStore, nextId } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";
import { synthesizeAnswerWithStepFun } from "../src/qa/src/stepfun-answerer.js";
import type { EnrichmentResult, IntelItem, QueryTurn, RawDoc } from "@safetrace/shared";
import { runIngestOnce } from "@safetrace/ingest";
import { runEnrichment } from "@safetrace/enrich";
import { buildRetrievalRequest } from "../src/qa/src/cli.js";
import { classifyIntent } from "../src/qa/src/q1-intent.js";
import { MemoryIndex, indexChunks, readFixtureChunks } from "../src/qa/src/q2-retrieval.js";

const MAX_BODY = 16_384;
const MODE = "fixture";

type Dataset = {
  store: MemoryEventStore;
  bus: EventBus;
  gateway?: ModelGateway;
  model_config_error?: string;
  fetched: RawDoc[];
  parsed: IntelItem[];
  intel: IntelItem[];
  enrichments: Map<string, EnrichmentResult>;
  index: MemoryIndex;
  chunkCount: number;
};

/** 每次启动重新跑离线采集和富化，不读取 web/src/mock.ts 或伪造看板数字。 */
export async function loadDataset(): Promise<Dataset> {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const result = await runIngestOnce({ store, offline: true });
  const intel = (await store.read<IntelItem>("intel.items")).map((e) => e.payload);
  const enriched = await runEnrichment(intel, { offline: true, bus });
  const index = new MemoryIndex({ bus });
  const chunks = readFixtureChunks();
  await indexChunks(index, chunks, {
    collection_name: "safetrace_chunks_local_demo", model_id: index.modelId,
    dim: 256, metric: "cosine",
  });
  let gateway: ModelGateway | undefined;
  let modelConfigError: string | undefined;
  try { gateway = new ModelGateway({ bus }); }
  catch { modelConfigError = "MG1 model configuration could not be loaded; Q4 template remains available"; }
  return {
    store, bus, gateway, ...(modelConfigError ? { model_config_error: modelConfigError } : {}),
    fetched: result.fetched, parsed: result.parsed, intel,
    enrichments: new Map(enriched.map((e) => [e.intel_id, e])), index,
    chunkCount: chunks.length,
  };
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}

function fail(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { error: { message }, data_mode: MODE });
}

async function bodyQuestion(req: import("node:http").IncomingMessage): Promise<string> {
  if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw new Error("请求必须是 JSON");
  const parts: Buffer[] = [];
  let length = 0;
  for await (const part of req) {
    const buf = part as Buffer;
    length += buf.length;
    if (length > MAX_BODY) throw new Error("问题超过 16KB 上限");
    parts.push(buf);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.concat(parts).toString("utf8")); }
  catch { throw new Error("请求体不是合法 JSON"); }
  const question = (parsed as { question?: unknown } | null)?.question;
  if (typeof question !== "string" || !question.trim() || question.length > 2000) {
    throw new Error("question 必须为 1–2000 字的非空字符串");
  }
  return question.trim();
}

function sourceDocs(data: Dataset, item: IntelItem): RawDoc[] {
  return data.fetched.filter((doc) => item.source_ids.includes(doc.source_id));
}

function itemView(data: Dataset, item: IntelItem) {
  const score = data.enrichments.get(item.intel_id)?.artifacts.score_assessment;
  const n = score?.cvss_v3_base ?? null;
  const docs = sourceDocs(data, item);
  return {
    id: item.intel_id, cve_id: item.cve_ids[0] ?? "", ghsa_id: item.ghsa_ids?.[0] ?? null,
    title: item.title, description: item.summary ?? item.title,
    severity: n === null ? "unknown" : n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low",
    cvss_score: n, cvss_vector: score?.cvss_v3_vector ?? null,
    cwe: item.entities.cwe, cpe: item.entities.cpes,
    ai_risk_category: null, exploit_status: null,
    published_at: item.published_at, fetched_at: docs[0]?.fetched_at ?? null,
    collect_latency_seconds: null, source_count: item.source_ids.length,
    enriched: data.enrichments.has(item.intel_id), summary: item.summary ?? "",
    data_mode: MODE,
  };
}

function evidenceView(data: Dataset, item: IntelItem) {
  const enriched = data.enrichments.get(item.intel_id);
  const docs = sourceDocs(data, item);
  const evidence = docs.map((doc, index) => ({
    evidence_id: "ev-" + (index + 1), source: doc.source_id, url: doc.url,
    snippet: "IntelItem 归并摘要（非逐源原文）：" + (item.summary ?? item.title) + "；payload_ref=" + doc.payload_ref, fetched_at: doc.fetched_at, raw_item_id: doc.external_id,
  }));
  const dimensions = [];
  if (enriched?.artifacts.score_assessment) {
    const score = enriched.artifacts.score_assessment;
    dimensions.push({ dimension: "cvss", value: { base: score.cvss_v3_base, vector: score.cvss_v3_vector, source: score.source_of_score },
      source: [score.source_of_score], evidence: evidence.filter((ev) => ev.source.includes(score.source_of_score)),
      confidence: score.confidence ?? 0, model: "rule", agent: "f4", version: 1,
      mock: true, degraded_to: MODE, degraded_reason: "离线 fixture 回放", created_at: enriched.completed_at });
  }
  if (enriched?.artifacts.papers?.length) {
    dimensions.push({ dimension: "paper", value: { papers: enriched.artifacts.papers.map((p) => p.title) },
      source: [...new Set(enriched.artifacts.papers.map((p) => p.source))],
      evidence: enriched.artifacts.papers.map((p) => ({ source: p.source, url: p.source === "arxiv" ? "https://arxiv.org/abs/" + p.paper_id : null,
        snippet: p.title, fetched_at: null })),
      confidence: Math.max(...enriched.artifacts.papers.map((p) => p.confidence)), model: "rule", agent: "f1",
      version: 1, mock: true, degraded_to: MODE, degraded_reason: "离线 fixture 回放", created_at: enriched.completed_at });
  }
  return { enrichments: dimensions, graph: { nodes: [], edges: [] }, data_mode: MODE };
}

function overview(data: Dataset, qaCount: number) {
  const n = data.intel.length;
  const enriched = [...data.enrichments.values()];
  const paper = enriched.filter((e) => e.dimensions_completed.includes("paper"));
  const cvss = enriched.filter((e) => e.dimensions_completed.includes("cvss"));
  const dim = (rows: EnrichmentResult[], kind: "paper" | "cvss") => {
    const confidences = rows.flatMap((row) => kind === "paper"
      ? (row.artifacts.papers ?? []).map((paper) => paper.confidence)
      : row.artifacts.score_assessment?.confidence === undefined ? [] : [row.artifacts.score_assessment.confidence]);
    return { records: rows.length, coverage_ratio: n ? rows.length / n : 0,
      confidence_avg: confidences.length ? confidences.reduce((sum, value) => sum + value, 0) / confidences.length : null,
      degraded_ratio: 1, mock_ratio: 1 };
  };
  return {
    data_mode: MODE,
    collect: { raw_items: data.fetched.length, vulns: n,
      merge_ratio: data.parsed.length ? 1 - data.intel.length / data.parsed.length : 0,
      sources: data.fetched.length },
    // published_at 属于历史 fixture，不能用它与本次 fetched_at 计算真实时效 SLA。
    latency: { p50_seconds: null, p95_seconds: null, sla_6h_ratio: null },
    enrich: { coverage_ratio: n ? enriched.length / n : 0, records: enriched.length, dimensions: 2,
      degraded_ratio: 1, per_dimension: { paper: dim(paper, "paper"), cvss: dim(cvss, "cvss") } },
    knowledge: { chunks: data.chunkCount }, agents: { runs: qaCount, failed: 0 },
    cost: { total_cny: null, daily_budget_cny: null, degraded: true, breakdown: {} },
  };
}

function sendSse(res: ServerResponse, value: Record<string, unknown>): void {
  if (!res.destroyed) res.write("data: " + JSON.stringify(value) + "\n\n");
}

/** 返回可测的 HTTP server；不在 import 时启动，测试可用随机端口。 */
export function createLocalDemoServer(data: Dataset, options: { diagnosticsDbPath?: string } = {}): Server {
  let qaCount = 0;
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const path = url.pathname;
      if (req.method === "GET" && path === "/api/v1/health") {
        const answerer = data.gateway?.roles().find((role) => role.role === "answerer");
        const stepfunReady = answerer?.provider === "stepplan" && Boolean(process.env.STEP_PLAN_API_KEY);
        sendJson(res, 200, { status: "ok", data_mode: MODE, degraded_to: MODE,
          source_count: data.fetched.length, intel_count: data.intel.length, chunk_count: data.chunkCount,
          qa_mode: stepfunReady ? "stepfun" : "template", qa_model: stepfunReady ? answerer.model_id : "q4-template",
          ...(data.model_config_error ? { qa_config_warning: data.model_config_error } : {}) });
        return;
      }
      if (req.method === "GET" && path === "/api/v1/ingest/diagnostics") {
        sendJson(res, 200, readIngestDiagnostics(options.diagnosticsDbPath));
        return;
      }
      if (req.method === "GET" && path === "/api/v1/metrics/overview") {
        sendJson(res, 200, overview(data, qaCount)); return;
      }
      if (req.method === "GET" && path === "/api/v1/collect/status") {
        sendJson(res, 200, { data_mode: MODE, queue_depth: 0,
          watermarks: data.fetched.map((doc) => ({ source: doc.source_id, last_sync_at: doc.fetched_at,
            last_full_sync_at: null, last_published_at: null, items_last_run: data.parsed.filter((it) => it.source_ids.includes(doc.source_id)).length,
            success: true, error: null })) }); return;
      }
      if (req.method === "GET" && path === "/api/v1/vulns") {
        const page = Number(url.searchParams.get("page") ?? "1");
        const size = Number(url.searchParams.get("page_size") ?? "20");
        if (!Number.isInteger(page) || page < 1 || !Number.isInteger(size) || size < 1 || size > 100) {
          fail(res, 400, "page/page_size 不合法"); return;
        }
        const q = (url.searchParams.get("q") ?? "").toLowerCase();
        const severity = url.searchParams.get("severity") ?? "";
        const poc = url.searchParams.get("has_poc") ?? "";
        const sort = url.searchParams.get("sort") ?? "published_at";
        if (!["", "true", "false"].includes(poc) || !["published_at", "fetched_at", "cvss_score"].includes(sort)) {
          fail(res, 400, "筛选/排序参数不合法"); return;
        }
        const rows = data.intel.map((item) => itemView(data, item)).filter((item) =>
          (!q || [item.title, item.description, item.cve_id].some((v) => v.toLowerCase().includes(q))) &&
          (!severity || item.severity === severity) && (poc === ""));
        rows.sort((a, b) => sort === "cvss_score" ? (b.cvss_score ?? -1) - (a.cvss_score ?? -1)
          : String(sort === "published_at" ? b.published_at ?? "" : b.fetched_at ?? "")
            .localeCompare(String(sort === "published_at" ? a.published_at ?? "" : a.fetched_at ?? "")));
        sendJson(res, 200, { items: rows.slice((page - 1) * size, page * size), total: rows.length,
          page, page_size: size, data_mode: MODE }); return;
      }
      const match = /^\/api\/v1\/vulns\/([^/]+)(\/evidence)?$/.exec(path);
      if (req.method === "GET" && match) {
        const item = data.intel.find((v) => v.intel_id === decodeURIComponent(match[1]!));
        if (!item) { fail(res, 404, "情报不存在"); return; }
        sendJson(res, 200, match[2] ? evidenceView(data, item) : itemView(data, item)); return;
      }
      if (req.method === "POST" && path === "/api/v1/qa/chat") {
        let question: string;
        try { question = await bodyQuestion(req); }
        catch (error) { fail(res, 400, (error as Error).message); return; }
        res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache, no-transform", connection: "keep-alive", "x-accel-buffering": "no" });
        const trace = nextId("tr");
        try {
          const turn: QueryTurn = { text: question, session_id: nextId("sess"), turn_id: nextId("turn") };
          const plan = classifyIntent(turn);
          sendSse(res, { event: "stage", stage: "plan", intent: plan.intents[0] ?? null });
          const retrieval = await data.index.search(buildRetrievalRequest(question, plan, trace));
          const retrievalLineage = await data.bus.readLineage(trace, 0, 1000);
          const retrievalLineageIds = retrievalLineage.map((row) => row.lineage_id);
          sendSse(res, { event: "stage", stage: "retrieve", hit: retrieval.chunks.length });
          const answerer = data.gateway?.roles().find((role) => role.role === "answerer");
          const answerProvider = answerer?.provider ?? "cache";
          const answerModelId = answerer?.model_id ?? "q4-template-v1";
          const stepfunReady = answerProvider === "stepplan" && Boolean(process.env.STEP_PLAN_API_KEY);
          sendSse(res, { event: "stage", stage: "generate", answer_mode: stepfunReady ? "stepfun" : "template" });
          const generated = await synthesizeAnswerWithStepFun(question, plan, retrieval, {
            session_id: turn.session_id, turn_id: turn.turn_id, bus: data.bus, parent_lineage_ids: retrievalLineageIds,
            provider: answerProvider, modelId: answerModelId, apiKeyConfigured: Boolean(process.env.STEP_PLAN_API_KEY),
            ...(data.gateway ? { client: data.gateway } : {}),
          });
          const answer = generated.answer;
          for (const cite of answer.citations) {
            const chunk = retrieval.chunks.find((v) => v.chunk_id === cite.chunk_id);
            sendSse(res, { event: "citation", id: cite.chunk_id, title: chunk?.doc_type ?? "证据",
              url: cite.url, score: chunk?.score_rerank ?? 0 });
          }
          sendSse(res, { event: "token", text: answer.text_md });
          qaCount++;
          sendSse(res, { event: "done", abstained: answer.abstained, confidence: answer.confidence,
            degraded: true, degraded_to: MODE, data_mode: MODE, trace_id: trace, cost_cny: null,
            answer_mode: generated.answer_mode, answer_model_id: generated.model_id ?? null,
            answer_fallback: generated.answer_mode === "template_fallback", fallback_reason: generated.fallback_reason ?? null });
        } catch (error) {
          sendSse(res, { event: "error", message: error instanceof Error ? error.message : String(error) });
        }
        res.end(); return;
      }
      fail(res, 404, "未找到接口");
    } catch (error) {
      fail(res, 500, error instanceof Error ? error.message : String(error));
    }
  });
}

async function start(): Promise<void> {
  const data = await loadDataset();
  const server = createLocalDemoServer(data);
  const port = Number(process.env.PORT ?? "8000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT 必须为 1-65535");
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const answerer = data.gateway?.roles().find((role) => role.role === "answerer");
  const stepfunReady = answerer?.provider === "stepplan" && Boolean(process.env.STEP_PLAN_API_KEY);
  const qaMode = stepfunReady ? "StepFun " + answerer.model_id + "（失败回退 Q4 模板）" : "Q4 规则模板";
  console.log("SafeTrace 本地链路已启动：http://127.0.0.1:" + port + "（采集/证据=fixture；Q&A=" + qaMode + "；StepFun 仅接收公开情报问题与检索证据，不接实时采集）");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
}
