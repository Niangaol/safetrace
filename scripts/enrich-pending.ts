import { degrade, EventBus, nextId, sha256Json, SqliteEventStore } from "@safetrace/shared";
import type { EnrichmentResult, IntelItem, QualityVerdict } from "@safetrace/shared";
import { createStepFunPaperReviewer, runEnrichment } from "@safetrace/enrich";
import type { PaperReviewPort } from "@safetrace/enrich";
import { ModelGateway } from "@safetrace/gateway";
import { setTimeout as sleep } from "node:timers/promises";
import { resolve } from "node:path";

function readLimit(): number {
  const arg = process.argv.find((value) => value.startsWith("--limit="));
  const value = Number(arg?.slice("--limit=".length) ?? process.env.SAFETRACE_ENRICH_BATCH_SIZE ?? "20");
  if (!Number.isInteger(value) || value < 1 || value > 500) throw new Error("--limit 必须为 1–500 的整数");
  return value;
}

async function readAll<T>(store: SqliteEventStore, topic: "intel.items" | "dq.verdicts" | "enrich.items"): Promise<T[]> {
  const values: T[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<T>(topic, offset, 500);
    values.push(...page.map((event) => event.payload));
    if (page.length < 500) return values;
  }
}

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_ENRICH_OFFLINE !== "false";
  const previousOfflineFixtures = process.env.OFFLINE_FIXTURES;
  const limit = readLimit();
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    process.env.OFFLINE_FIXTURES = offline ? "true" : "false";
    const [intelEvents, verdictEvents, enrichEvents] = await Promise.all([
      readAll<IntelItem>(store, "intel.items"),
      readAll<QualityVerdict>(store, "dq.verdicts"),
      readAll<EnrichmentResult>(store, "enrich.items"),
    ]);
    const latestIntel = new Map<string, IntelItem>();
    for (const item of intelEvents) latestIntel.set(item.intel_id, item);
    const accepted = new Set(verdictEvents.filter((item) => item.verdict === "pass" || item.verdict === "degrade").map((item) => item.item_id));
    const completed = new Set(enrichEvents.map((item) => item.intel_id));
    const pending = [...latestIntel.values()].filter((item) => accepted.has(item.intel_id) && !completed.has(item.intel_id));
    const batch = pending.slice(0, limit);
    const traceId = nextId("tr_enrich_batch");
    const llmOptIn = process.env.SAFETRACE_ENRICH_LLM_ENABLED === "true";
    let paperReviewer: PaperReviewPort | undefined;
    if (llmOptIn) {
      if (offline) {
        await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "rejected", decision: { reason: "StepPlan F1 advisory requested in fixture/offline mode; no model request made" } });
        await degrade({ layer: "L3", trigger: "F1 StepPlan advisory requested while enrichment is offline", degradedOf: "rule-ranked-papers", traceId, label: "离线富化不调用 StepPlan；保留规则结果", recoveryHint: "需在线检索时设置 SAFETRACE_ENRICH_OFFLINE=false，并单独开启 SAFETRACE_ENRICH_LLM_ENABLED=true。", emit: async (event) => { await bus.publish("fallback.events", event, { trace_id: traceId }); } });
      } else {
        const gateway = new ModelGateway({ bus });
        const planner = gateway.roles().find((role) => role.role === "planner");
        const keyConfigured = Boolean(process.env.STEP_PLAN_API_KEY);
        if (planner?.provider === "stepplan" && keyConfigured) {
          paperReviewer = createStepFunPaperReviewer({ provider: planner.provider, modelId: planner.model_id, apiKeyConfigured: true, client: gateway });
          await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "success", input_refs: [{ kind: "ModelRole", id: "planner", sha256: sha256Json({ provider: planner.provider, model_id: planner.model_id }) }], decision: { reason: "F1 model is advisory-only; live, ambiguous public arXiv metadata required" } });
        } else {
          await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "rejected", decision: { reason: "StepPlan F1 advisory requested but planner/key is not configured" } });
          await degrade({ layer: "L3", trigger: "F1 StepPlan advisory requested but StepPlan planner/key is unavailable", degradedOf: "rule-ranked-papers", traceId, label: "StepPlan 论文建议不可用；沿用规则富化", recoveryHint: "选择 StepPlan planner profile 并配置本机 STEP_PLAN_API_KEY。", emit: async (event) => { await bus.publish("fallback.events", event, { trace_id: traceId }); } });
        }
      }
    }
    const delayMs = offline ? 0 : Math.max(3000, Number(process.env.SAFETRACE_ENRICH_DELAY_MS ?? "3000"));
    console.log(JSON.stringify({ mode: offline ? "fixture/offline" : "live", db_path: dbPath, unique_intel_ids: latestIntel.size, accepted_ids: accepted.size, already_enriched: completed.size, pending: pending.length, batch_size: batch.length, delay_ms_between_live_items: delayMs, stepplan_f1_advisory_active: Boolean(paperReviewer), trace_id: traceId }));
    for (let index = 0; index < batch.length; index++) {
      if (index > 0 && delayMs > 0) await sleep(delayMs);
      const item = batch[index]!;
      await runEnrichment([item], {
        offline, bus, traceId, ...(paperReviewer ? { paperReviewer } : {}),
        onPaperReview: (intelId, outcome) => console.log(JSON.stringify({ type: "f1_stepfun_advisory", intel_id: intelId, status: outcome.status, ...(outcome.status === "suggested" ? { paper_ids: outcome.paper_ids, model_confidence: outcome.confidence } : { reason: outcome.reason }), applied: false })),
      });
      if ((index + 1) % 5 === 0 || index + 1 === batch.length) console.log("enriched", index + 1, "/", batch.length, item.intel_id);
    }
    console.log(JSON.stringify({ completed_this_batch: batch.length, pending_after_batch: Math.max(0, pending.length - batch.length), mode: offline ? "fixture/offline" : "live", trace_id: traceId }));
  } finally {
    if (previousOfflineFixtures === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = previousOfflineFixtures;
    store.close();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
