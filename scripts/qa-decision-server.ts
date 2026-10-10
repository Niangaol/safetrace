import { resolve, dirname } from "node:path";
import { mkdir, readFile } from "node:fs/promises";
import { EventBus, SqliteEventStore, SqliteLlmContextStore } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";
import { createStepPlanDecisionHandler } from "@safetrace/qa";
import { createGatewayServer } from "../src/gateway/src/server.js";

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const contextStore = new SqliteLlmContextStore(dbPath);
  const bus = new EventBus({ store });
  const gateway = new ModelGateway({ bus, contextStore });
  const planner = gateway.roles().find((role) => role.role === "planner");
  // 本地 Open-Jev 兜底通道：显式配置 JEV_MODEL_ID 才启用（钉版本，禁会漂移别名）。
  // 云 StepPlan 仍排在前面；本地不可用时由 ladder 显式下坠人工层，不静默跳过。
  const jevModelId = process.env.JEV_MODEL_ID?.trim();
  const jevProvenance = await (async () => {
    const path = process.env.JEV_PROVENANCE_FILE?.trim();
    if (!path) return undefined;
    const parsed = JSON.parse(await readFile(resolve(path), "utf8")) as Record<string, unknown>;
    for (const key of ["model", "checkpoint_sha256", "base_revision", "code_commit"]) {
      if (typeof parsed[key] !== "string" || !parsed[key]) throw new Error("JEV_PROVENANCE_FILE 必须含 model/checkpoint_sha256/base_revision/code_commit");
    }
    return parsed as unknown as { model: string; checkpoint_sha256: string; base_revision: string; code_commit: string; model_revision?: string; device?: string };
  })();
  const decideHandler = createStepPlanDecisionHandler({
    provider: planner?.provider ?? "cache",
    modelId: planner?.model_id ?? "unconfigured",
    apiKeyConfigured: Boolean(process.env.STEP_PLAN_API_KEY),
    client: gateway,
    bus,
    // 未决请求与 decision.replies 共用同一 SQLite 库，供 human:queue 查询/接单/决单。
    ticketStore: store,
    ...(jevModelId ? { openjev: { modelId: jevModelId, ...(jevProvenance ? { expectedProvenance: jevProvenance } : {}) } } : {}),
  });
  const port = Number(process.env.DECISION_PORT ?? 8317);
  const app = createGatewayServer({ gateway, bus, port, host: "127.0.0.1", decideHandler });
  app.server.once("close", () => { contextStore.close(); store.close(); });
  await app.listen();
  console.log("SafeTrace A-02 gateway listening on http://127.0.0.1:" + app.port + "; StepPlan requires public opt-in + screened public facts + calibrated option probabilities; local Open-Jev fallback " + (jevModelId ? "enabled (" + jevModelId + (jevProvenance ? ", provenance pinned" : ", provenance UNPINNED") + ")" : "disabled (set JEV_MODEL_ID to enable)") + ".");
  const close = (): void => { app.server.close(); };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

void main().catch((error: unknown) => {
  console.error("A-02 gateway failed: " + (error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});
