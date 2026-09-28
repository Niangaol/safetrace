/**
 * Q 线检索 HTTP 服务（contracts/openapi.yaml：/healthz、/v1/retrieve）。
 * 端口默认 8318（env PORT 覆盖）；请求体按 contracts/schemas/RetrievalRequest.json 运行期校验。
 */
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { validateInstance } from "@safetrace/shared";
import type { RetrievalRequest, SchemaLike } from "@safetrace/shared";
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
export async function createDefaultEngine(): Promise<RetrievalEngine> {
  const url = process.env.QDRANT_URL;
  if (url) {
    return new QdrantEngine({ url, collection: process.env.QDRANT_COLLECTION ?? "safetrace_chunks" });
  }
  const memory = new MemoryIndex();
  await indexChunks(memory, readFixtureChunks(), {
    collection_name: "safetrace_chunks",
    model_id: memory.modelId,
    dim: 256,
    metric: "cosine",
  });
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
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  const parts: Buffer[] = [];
  let size = 0;
  for await (const part of req) {
    const buf = part as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) return { ok: false, error: "请求体超过 1MB 上限" };
    parts.push(buf);
  }
  const raw = Buffer.concat(parts).toString("utf8");
  if (raw.trim().length === 0) return { ok: false, error: "请求体为空" };
  try {
    return { ok: true, value: JSON.parse(raw) as unknown };
  } catch {
    return { ok: false, error: "请求体不是合法 JSON" };
  }
}

/** 建服务（测试注入引擎用；不监听端口）。 */
export function createServer(engine: RetrievalEngine): Server {
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
          sendJson(res, 400, { error: "invalid_request", errors });
          return;
        }
        const resp = await engine.search(parsed.value as RetrievalRequest);
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
export async function startServer(opts: { port?: number; engine?: RetrievalEngine } = {}): Promise<Server> {
  const engine = opts.engine ?? (await createDefaultEngine());
  const port = opts.port ?? Number(process.env.PORT ?? DEFAULT_PORT);
  const server = createServer(engine);
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
