/**
 * MG1 HTTP 服务（contracts/openapi.yaml）：
 * GET /healthz；POST /v1/chat/complete；POST /v1/embed；POST /v1/rerank。
 * D4 的 /v1/decide 由问答线编排层接入后在此挂载（P0 预留路由位）。
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, SqliteEventStore } from "@safetrace/shared";
import type { EventBus as EventBusType } from "@safetrace/shared";
import { ModelGateway } from "./index.js";
import type { ChatMessage, ChatParams } from "./types.js";

export interface ServerOptions {
  port?: number;
  gateway?: ModelGateway;
  bus?: EventBusType;
  /** A-02：/v1/decide 决策阶梯处理器（问答线编排层注入）。 */
  decideHandler?: (req: unknown) => Promise<unknown>;
}

export function createGatewayServer(opts: ServerOptions = {}) {
  const ownsStore = opts.bus === undefined && opts.gateway === undefined;
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  mkdirSync(dirname(dbPath), { recursive: true });
  const store = ownsStore ? new SqliteEventStore(dbPath) : undefined;
  const bus = opts.bus ?? (store ? new EventBus({ store }) : undefined);
  const gw = opts.gateway ?? new ModelGateway({ ...(bus ? { bus } : {}) });
  const port = opts.port ?? Number(process.env.PORT ?? 8317);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/healthz") {
        const circuits = gw.circuitStates();
        const open = circuits.filter((c) => c.status === "open");
        sendJson(res, 200, {
          status: "ok",
          degraded_to: open.length > 0 ? "provider_circuit_open:" + open.map((c) => c.key).join(",") : "",
          roles: gw.roles(),
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/chat/complete") {
        const body = await readJson(req);
        const role = String(body.role ?? "");
        const messages = (body.messages ?? []) as ChatMessage[];
        const params = (body.params ?? {}) as ChatParams;
        const traceId = String(body.trace_id ?? nextId("tr"));
        const dataDomain = body.data_domain === "private" ? "private" : body.data_domain === "public" ? "public" : undefined;
        const reply = await gw.chat(role as never, messages, params, traceId, dataDomain);
        sendJson(res, 200, reply);
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/embed") {
        const body = await readJson(req);
        const dataDomain = body.data_domain === "private" ? "private" : body.data_domain === "public" ? "public" : undefined;
        const emb = await gw.embed(String(body.role ?? "") as never, (body.texts ?? []) as string[], String(body.trace_id ?? nextId("tr")), dataDomain);
        sendJson(res, 200, emb);
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/decide") {
        // A-02：四层兜底阶梯入口。decideHandler 由问答线编排层注入（ladder）；
        // 未注入时明确 501，不假装能决策。
        const handler = opts.decideHandler;
        if (!handler) {
          sendJson(res, 501, { error: "not_implemented", message: "/v1/decide 尚未挂接决策阶梯（A-02 注入 decideHandler）" });
          return;
        }
        const body = await readJson(req);
        const reply = await handler(body as never);
        sendJson(res, 200, reply);
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/rerank") {
        const body = await readJson(req);
        const ranked = await gw.rerank(String(body.role ?? "") as never, String(body.query ?? ""), (body.docs ?? []) as string[], String(body.trace_id ?? nextId("tr")));
        sendJson(res, 200, ranked);
        return;
      }
      sendJson(res, 404, { error: "not_found", path: url.pathname });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const status = msg.includes("未配置") ? 400 : 503;
      sendJson(res, status, { error: msg, degraded_to: "request_failed" });
    }
  });

  if (store) server.once("close", () => store.close());
  return { server, port, listen: () => new Promise<void>((resolve) => server.listen(port, resolve)) };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(payload);
}

// 直接运行：tsx src/gateway/src/server.ts
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const { port, listen } = createGatewayServer();
  listen().then(() => console.log("[MG1] listening on http://127.0.0.1:" + port));
}

function pathToFileURL(p: string): URL {
  return new URL("file://" + (p.startsWith("/") ? p : "/" + p.replace(/\\/g, "/")));
}
