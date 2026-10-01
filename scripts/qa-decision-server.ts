import { resolve, dirname } from "node:path";
import { mkdir } from "node:fs/promises";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";
import { createStepPlanDecisionHandler } from "@safetrace/qa";
import { createGatewayServer } from "../src/gateway/src/server.js";

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  const gateway = new ModelGateway({ bus });
  const planner = gateway.roles().find((role) => role.role === "planner");
  const decideHandler = createStepPlanDecisionHandler({
    provider: planner?.provider ?? "cache",
    modelId: planner?.model_id ?? "unconfigured",
    apiKeyConfigured: Boolean(process.env.STEP_PLAN_API_KEY),
    client: gateway,
    bus,
  });
  const port = Number(process.env.DECISION_PORT ?? 8317);
  const app = createGatewayServer({ gateway, bus, port, host: "127.0.0.1", decideHandler });
  app.server.once("close", () => store.close());
  await app.listen();
  console.log("SafeTrace A-02 gateway listening on http://127.0.0.1:" + app.port + "; StepPlan requires public opt-in + screened public facts + calibrated option probabilities.");
  const close = (): void => { app.server.close(); };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

void main().catch((error: unknown) => {
  console.error("A-02 gateway failed: " + (error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});
