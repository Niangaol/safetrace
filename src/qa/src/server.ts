/**
 * Q 线检索 HTTP 服务（contracts/openapi.yaml：/healthz、/v1/retrieve）。
 * 端口默认 8318（env PORT 覆盖）；请求体按 contracts/schemas/RetrievalRequest.json 运行期校验。
 */
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ModelGateway } from "@safetrace/gateway";
import { EventBus, nextId, sha256, sha256Json, validateInstance } from "@safetrace/shared";
import type { RetrievalRequest, SchemaLike } from "@safetrace/shared";
import { SqliteEventStore } from "@safetrace/shared";
import { MemoryIndex, QdrantEngine, indexChunks, readFixtureChunks } from "./q2-retrieval.js";
import type { RetrievalEngine } from "./q2-retrieval.js";

export const DEFAULT_PORT = 8318;
const MAX_BODY_BYTES = 1024 * 1024;
const DOC_TYPES = ["vuln_advisory", "vendor_advisory", "paper", "standard", "policy", "enrichment"] as const;

/** contracts/schemas/RetrievalRequest.json 的手工镜像（契约 JSON 不进 TS 编译链）。 */
const RETRIEVAL_REQUEST_SCHEMA: SchemaLike = {
  type: "object",
  additionalProperties: false,
  required: ["query_id", "query_text", "top_k", "trace_id", "schema_version"],
  properties: {
    query_id: { type: "string", minLength: 1 },
    query_text: { type: "string", minLength: 1 },
    top_k: { type: "integer", minimum: 1, maximum: 100 },
    doc_types: { type: "array" },
    cve_ids: { type: "array" },
    min_quality: { type: "number", minimum: 0, maximum: 1 },
    published_after: { type: "string", format: "date-time" },
    trace_id: { type: "string" },
    schema_version: { type: "string", pattern: "^[0-9]+\\.[0-9]+$" },
  },
};

/** 默认引擎：QDRANT_URL 已配置 → QdrantEngine（内部自带显式降级）；否则 MemoryIndex + fixtures 种子。 */
export async function createDefaultEngine(bus?: EventBus): Promise<RetrievalEngine> {
  const url = process.env.QDRANT_URL;
  if (url) {
    const gateway = new ModelGateway();
    const profile = gateway.embeddingProfile();
    const collection = process.env.QDRANT_COLLECTION ?? "safetrace_chunks";
    const engine = new QdrantEngine({
      url,
      collection,
      bus,
      api_key: process.env.QDRANT_API_KEY,
      model_id: profile.model_id,
      model_version: profile.model_version,
      embedding_dim: profile.dimension,
      embedder: (texts, traceId) => gateway.embed("embedder", texts, traceId),
    });
    if (process.env.QDRANT_SEED_FIXTURES === "true") {
      if (!profile.dimension) throw new Error("QDRANT_SEED_FIXTURES 需要在 embedder capability_flags.dim 配置真实向量维度");
      await indexChunks(engine, readFixtureChunks(), {
        collection_name: collection,
        model_id: profile.model_id,
        model_version: profile.model_version,
        dim: profile.dimension,
        metric: "cosine",
      }, { trace_id: nextId("tr") });
    }
    return engine;
  }
  const memory = new MemoryIndex({ bus });
  await indexChunks(memory, readFixtureChunks(), {
    collection_name: "safetrace_chunks",
    model_id: memory.modelId,
    dim: 256,
    metric: "cosine",
  }, { trace_id: nextId("tr") });
  return memory;
}

function healthPayload(engine: RetrievalEngine): { status: "ok"; degraded_to?: string } {
  const degraded = (engine as { lastDegradedTo?: string }).lastDegradedTo;
  return degraded ? { status: "ok", degraded_to: degraded } : { status: "ok" };
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

async function readJsonBody(
  req: IncomingMessage,
): Promise<{ ok: true; value: unknown; body_sha256: string } | { ok: false; error: string; body_sha256: string }> {
  const parts: Buffer[] = [];
  let size = 0;
  for await (const part of req) {
    const buf = part as Buffer;
    size += buf.length;
    parts.push(buf);
    if (size > MAX_BODY_BYTES) return { ok: false, error: "请求体超过 1MB 上限", body_sha256: sha256(Buffer.concat(parts)) };
  }
  const raw = Buffer.concat(parts).toString("utf8");
  if (raw.trim().length === 0) return { ok: false, error: "请求体为空", body_sha256: sha256(raw) };
  try {
    return { ok: true, value: JSON.parse(raw) as unknown, body_sha256: sha256(raw) };
  } catch {
    return { ok: false, error: "请求体不是合法 JSON", body_sha256: sha256(raw) };
  }
}

/** 建服务（测试注入引擎用；不监听端口）。 */
export function createServer(engine: RetrievalEngine, bus?: EventBus): Server {
  return createHttpServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method === "GET" && url.pathname === "/healthz") {
        sendJson(res, 200, healthPayload(engine));
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/retrieve") {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          const rejectedTraceId = "tr_rejected_" + parsed.body_sha256.slice(0, 16);
          await bus?.recordLineage({
            trace_id: rejectedTraceId,
            stage: "qa.http_validate",
            operation_version: "qa-retrieve-api.v1",
            status: "rejected",
            input_refs: [{ kind: "HttpRequestBody", id: rejectedTraceId, sha256: parsed.body_sha256 }],
            decision: { reason: parsed.error },
            error: "request body rejected; raw body omitted",
          });
          sendJson(res, 400, { error: "invalid_request", errors: [parsed.error] });
          return;
        }
        const errors = validateInstance(parsed.value, RETRIEVAL_REQUEST_SCHEMA);
        const body = parsed.value as Record<string, unknown>;
        const docTypes = body.doc_types;
        if (Array.isArray(docTypes) && docTypes.some((t) => !DOC_TYPES.includes(t as (typeof DOC_TYPES)[number]))) {
          errors.push("doc_types 含非法枚举值（合法值见 RetrievalRequest.json）");
        }
        if (errors.length > 0) {
          const requestHash = sha256Json(parsed.value);
          const suppliedTrace = typeof body.trace_id === "string" ? body.trace_id : "";
          const rejectedTraceId = suppliedTrace || "tr_rejected_" + requestHash.slice(0, 16);
          await bus?.recordLineage({
            trace_id: rejectedTraceId,
            stage: "qa.http_validate",
            operation_version: "qa-retrieve-api.v1",
            status: "rejected",
            input_refs: [{ kind: "HttpRequestBody", id: rejectedTraceId, sha256: requestHash }],
            decision: { reason: "schema validation rejected" },
            error: "request validation failed: " + errors.join("; "),
          });
          sendJson(res, 400, { error: "invalid_request", errors });
          return;
        }
        const request = parsed.value as RetrievalRequest;
        const validationRecord = await bus?.recordLineage({
          trace_id: request.trace_id,
          stage: "qa.http_validate",
          operation_version: "qa-retrieve-api.v1",
          status: "success",
          input_refs: [{ kind: "RetrievalRequest", id: request.query_id, sha256: sha256Json(request) }],
          output_refs: [{ kind: "ValidatedRetrievalRequest", id: request.query_id, sha256: sha256Json(request) }],
        });
        const lineageOffset = bus ? (await bus.readLineage(request.trace_id)).length : 0;
        let resp;
        try {
          resp = await engine.search(request, {
            ...(validationRecord ? { parent_lineage_ids: [validationRecord.lineage_id] } : {}),
            causation_id: null,
          });
        } catch {
          await bus?.recordLineage({
            trace_id: request.trace_id,
            parent_lineage_ids: validationRecord ? [validationRecord.lineage_id] : [],
            stage: "qa.http_retrieve",
            operation_version: "qa-retrieve-api.v1",
            status: "failed",
            input_refs: [{ kind: "RetrievalRequest", id: request.query_id, sha256: sha256Json(request) }],
            error: "retrieval engine failed; request content omitted",
          });
          throw new Error("retrieval failed; trace_id=" + request.trace_id);
        }
        const traceRecords = bus ? await bus.readLineage(request.trace_id, lineageOffset) : [];
        const q2Parent = traceRecords.filter((record) => record.stage.startsWith("q2.")).at(-1)?.lineage_id;
        await bus?.recordLineage({
          trace_id: request.trace_id,
          parent_lineage_ids: [validationRecord?.lineage_id, q2Parent].filter((id): id is string => Boolean(id)),
          stage: "qa.http_response",
          operation_version: "qa-retrieve-api.v1",
          status: resp.degraded_to ? "degraded" : "success",
          input_refs: [{ kind: "RetrievalRequest", id: request.query_id, sha256: sha256Json(request) }],
          output_refs: [
            { kind: "RetrievalResponse", id: resp.query_id, sha256: sha256Json(resp) },
            ...resp.chunks.map((chunk) => ({ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
          ],
          execution: { component_version: "qa-retrieve-api.v1", model_id: resp.embedder_model_id },
          ...(resp.degraded_to ? { decision: { fallback_to: resp.degraded_to, reason: "retriever degraded" } } : {}),
        });
        sendJson(res, 200, resp);
        return;
      }
      if (url.pathname === "/v1/retrieve" || url.pathname === "/healthz") {
        sendJson(res, 405, { error: "method_not_allowed" });
        return;
      }
      sendJson(res, 404, { error: "not_found" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: "internal", message: msg });
    }
  });
}

/** 起服务（qa:serve 入口）。 */
export async function startServer(opts: { port?: number; engine?: RetrievalEngine; bus?: EventBus } = {}): Promise<Server> {
  const ownsStore = opts.bus === undefined;
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = ownsStore ? new SqliteEventStore(dbPath) : undefined;
  const bus = opts.bus ?? new EventBus({ store: store! });
  const engine = opts.engine ?? (await createDefaultEngine(bus));
  const port = opts.port ?? Number(process.env.PORT ?? DEFAULT_PORT);
  const server = createServer(engine, bus);
  if (store) server.once("close", () => store.close());
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  return server;
}

function isMainEntry(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isMainEntry()) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  void startServer({ port }).then((server) => {
    const addr = server.address();
    const bound = addr && typeof addr === "object" ? addr.port : port;
    console.log("qa retrieve server listening on http://127.0.0.1:" + bound + "（GET /healthz，POST /v1/retrieve）");
  });
}
