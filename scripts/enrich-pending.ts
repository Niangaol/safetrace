import { degrade, EventBus, nextId, sha256Json, SqliteEventStore, SqliteLlmContextStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import type { EnrichmentResult, FallbackEvent, IntelItem, QualityVerdict } from "@safetrace/shared";
import { nextArxivFailureStreak, planPendingEnrichment } from "../src/enrich/src/pending.js";
import { createJevPaperReviewer, createStepFunPaperReviewer, runEnrichment } from "@safetrace/enrich";
import type { PaperReviewPort } from "@safetrace/enrich";
import { ModelGateway } from "@safetrace/gateway";
import { setTimeout as sleep } from "node:timers/promises";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { fileURLToPath } from "node:url";

function readLimit(): number {
  const arg = process.argv.find((value) => value.startsWith("--limit="));
  const value = Number(arg?.slice("--limit=".length) ?? process.env.SAFETRACE_ENRICH_BATCH_SIZE ?? "20");
  if (!Number.isInteger(value) || value < 1 || value > 500) throw new Error("--limit 必须为 1–500 的整数");
  return value;
}

async function readAll<T>(store: DatabaseSync, topic: "intel.items" | "dq.verdicts" | "enrich.items"): Promise<T[]> {
  const values: T[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = store.prepare("SELECT payload FROM events WHERE topic=? ORDER BY seq LIMIT 500 OFFSET ?").all(topic, offset) as { payload: string }[];
    values.push(...page.map(event => JSON.parse(event.payload) as T));
    if (page.length < 500) return values;
  }
}

function publishedEnrichments(reader: DatabaseSync) {
  return reader.prepare("SELECT event_id,payload FROM events WHERE topic='enrich.items' ORDER BY seq").all().map(row => ({ event_id: String(row.event_id), payload: JSON.parse(String(row.payload)) as EnrichmentResult }));
}

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_ENRICH_OFFLINE !== "false";
  const previousOfflineFixtures = process.env.OFFLINE_FIXTURES;
  const limit = readLimit();
  const apply = process.argv.includes("--apply");
  if (apply && process.argv.includes("--dry-run")) throw new Error("--apply 与 --dry-run 不可同时使用");
  if (apply) await requireVerifiedBackup(dbPath);
  const releaseLease = apply ? acquireIntelIndexLease("http://127.0.0.1", "enrichment-db:" + dbPath, fileURLToPath(new URL("../.tmp/data-maintenance-locks/", import.meta.url))) : undefined;
  const reader = new DatabaseSync(dbPath, { readOnly: true });
  let store: SqliteEventStore | undefined;
  let stateStore = new SqliteEnrichmentStateStore(dbPath, { readOnly: true });
  let contextStore: SqliteLlmContextStore | undefined;
  let bus: EventBus;
  try {
    process.env.OFFLINE_FIXTURES = offline ? "true" : "false";
    const [intelEvents, verdictEvents, enrichEvents] = await Promise.all([
      readAll<IntelItem>(reader, "intel.items"),
      readAll<QualityVerdict>(reader, "dq.verdicts"),
      readAll<EnrichmentResult>(reader, "enrich.items"),
    ]);
    const snapshot = readIntelIndexSnapshot(dbPath);
    const releasedItems = [...snapshot.accepted.values()].map(entry => entry.item);
    const dimensionsArg = process.argv.find(value => value.startsWith("--dimensions="))?.slice("--dimensions=".length);
    const dimensions = dimensionsArg === undefined ? undefined : ([...new Set(dimensionsArg.split(",").map(v => v.trim()).filter(Boolean))] as string[]);
    if (dimensions !== undefined && (dimensions.length === 0 || dimensions.some(d => !["paper","cvss","epss"].includes(d)))) throw new Error("--dimensions 只能取 paper,cvss,epss 的非空子集");
    const scope = dimensions as readonly ("paper"|"cvss"|"epss")[] | undefined;
    const plan = planPendingEnrichment(releasedItems, [...snapshot.accepted.values()].map(entry => entry.verdict), enrichEvents, { states: stateStore.list(), publishedEnrichments: publishedEnrichments(reader), currentIntelEventIds: new Map([...snapshot.accepted].map(([id, entry]) => [id, entry.intel_event.event_id])), ...(scope ? { dimensions: scope } : {}) });
    const pending = plan.pending;
    const sourceArg = process.argv.find(value => value.startsWith("--source="))?.slice("--source=".length);
    if (sourceArg !== undefined && !/^[a-z0-9_]+$/.test(sourceArg)) throw new Error("--source 必须为有效 source_id");
    const recheckArg = process.argv.find(value => value.startsWith("--recheck-ids="))?.slice("--recheck-ids=".length);
    const recheckIds = recheckArg === undefined ? undefined : new Set(recheckArg.split(",").filter(Boolean));
    if (recheckIds && recheckIds.size === 0) throw new Error("--recheck-ids 不得为空");
    const candidates = recheckIds ? plan.accepted_items.filter(item => recheckIds.has(item.intel_id)) : pending;
    if (recheckIds && candidates.length !== recheckIds.size) throw new Error("复核 id 不存在或最新 DQ 判定未放行；不执行复核");
    const selected = sourceArg ? candidates.filter(item => item.source_ids.includes(sourceArg)) : candidates;
    const batch = selected.slice(0, limit);
    if (!apply) {
      console.log(JSON.stringify({ dry_run: true, db_path: dbPath, accepted_ids: plan.accepted_ids, pending: pending.length, batch_size: batch.length, real_live_dimensions: plan.real_live_dimensions, selected: batch.map(item => ({ intel_id: item.intel_id, latestDQ: plan.latestDQ.get(item.intel_id)?.verdict, dimensions: plan.pending_dimensions.get(item.intel_id) })), writes: 0 }));
      return;
    }
    stateStore.close();
    stateStore = new SqliteEnrichmentStateStore(dbPath);
    store = new SqliteEventStore(dbPath);
    bus = new EventBus({ store });
    const traceId = nextId("tr_enrich_batch");
    const llmOptIn = process.env.SAFETRACE_ENRICH_LLM_ENABLED === "true";
    let paperReviewer: PaperReviewPort | undefined;
    if (llmOptIn) {
      if (offline) {
        await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "rejected", decision: { reason: "StepPlan F1 advisory requested in fixture/offline mode; no model request made" } });
        await degrade({ layer: "L3", trigger: "F1 StepPlan advisory requested while enrichment is offline", degradedOf: "rule-ranked-papers", traceId, label: "离线富化不调用 StepPlan；保留规则结果", recoveryHint: "需在线检索时设置 SAFETRACE_ENRICH_OFFLINE=false，并单独开启 SAFETRACE_ENRICH_LLM_ENABLED=true。", emit: async (event) => { await bus.publish("fallback.events", event, { trace_id: traceId }); } });
      } else {
        contextStore = new SqliteLlmContextStore(dbPath);
        const gateway = new ModelGateway({ bus, contextStore });
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
    // 本地 Open-Jev 论文评审（SAFETRACE_ENRICH_PAPER_REVIEWER=jev）：与 StepFun 云端评审互斥，
    // 离线模式一律拒绝（fixture 回放必须确定）；模型标识钉版本，官方别名会静默漂移。
    const jevReviewerKind = process.env.SAFETRACE_ENRICH_PAPER_REVIEWER;
    if (jevReviewerKind !== undefined && jevReviewerKind !== "jev") throw new Error("SAFETRACE_ENRICH_PAPER_REVIEWER 只能取 jev（本地 Open-Jev 评审）");
    if (jevReviewerKind === "jev" && llmOptIn) throw new Error("SAFETRACE_ENRICH_PAPER_REVIEWER=jev 与 SAFETRACE_ENRICH_LLM_ENABLED=true 互斥：一次只启用一个论文评审端");
    let paperReviewerProvider: string | undefined;
    if (jevReviewerKind === "jev") {
      if (offline) {
        await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "rejected", decision: { reason: "Local Open-Jev F1 advisory requested in fixture/offline mode; no model request made" } });
        await degrade({ layer: "L3", trigger: "F1 Open-Jev advisory requested while enrichment is offline", degradedOf: "rule-ranked-papers", traceId, label: "离线富化不调用本地 Jev 评审；保留规则结果", recoveryHint: "需启用本地评审时设置 SAFETRACE_ENRICH_OFFLINE=false，并保持 Jev 服务（JEV_BASE_URL）就绪。", emit: async (event) => { await bus.publish("fallback.events", event, { trace_id: traceId }); } });
      } else {
        paperReviewer = createJevPaperReviewer({ modelId: process.env.JEV_MODEL_ID ?? "Open-Jev-2B", ...(process.env.JEV_BASE_URL ? { baseUrl: process.env.JEV_BASE_URL } : {}) });
        paperReviewerProvider = "openjev";
        await bus.recordLineage({ trace_id: traceId, stage: "enrich.llm_optin", operation_version: "enrich-llm-optin.v1", status: "success", input_refs: [{ kind: "ModelRole", id: "openjev", sha256: sha256Json({ base_url: process.env.JEV_BASE_URL ?? "http://127.0.0.1:8791", model_id: process.env.JEV_MODEL_ID ?? "Open-Jev-2B" }) }], decision: { reason: "F1 local Jev review is advisory-only; ambiguous rule-ranked arXiv candidates required" } });
      }
    }
    const requestedDelay = Number(process.env.SAFETRACE_ENRICH_DELAY_MS ?? "3000");
    const stopAfter = Number(process.env.SAFETRACE_ENRICH_STOP_AFTER_ARXIV_FAILURES ?? "3");
    if (!Number.isFinite(requestedDelay) || requestedDelay < 0 || !Number.isSafeInteger(stopAfter) || stopAfter < 1) throw new Error("富化延迟必须非负有限，连续失败阈值必须为正整数");
    // arXiv 礼让只在真的会发起 arXiv 请求时生效；只补 cvss/epss 的条目改用更短的服务礼节间隔。
    const delayFor = (): number => offline ? 0 : (scope === undefined || scope.includes("paper") ? Math.max(3000, requestedDelay) : Math.max(250, Math.min(requestedDelay, 1000)));
    console.log(JSON.stringify({ mode: offline ? "fixture/offline" : "live", db_path: dbPath, unique_intel_ids: plan.unique_intel_ids, accepted_ids: plan.accepted_ids, already_enriched: plan.already_enriched, recorded_with_failed_dimensions: plan.recorded_with_failed_dimensions, pending: pending.length, selected_source: sourceArg ?? null, recheck_recorded: Boolean(recheckIds), selected_count: selected.length, batch_size: batch.length, delay_ms_between_live_items: delayFor(), dimensions: scope ?? ["paper","cvss","epss"], f1_advisory_active: Boolean(paperReviewer), f1_advisory_provider: paperReviewerProvider ?? (llmOptIn ? "stepplan" : null), trace_id: traceId }));
    let processed = 0;
    let newlyProcessed = 0;
    const pendingIds = new Set(pending.map(item => item.intel_id));
    let consecutiveArxivFailures = 0;
    let stoppedForSourceFailure = false;
    for (let index = 0; index < batch.length; index++) {
      if (index > 0) await sleep(delayFor());
      const item = batch[index]!;
      const current = readIntelIndexSnapshot(dbPath).accepted.get(item.intel_id);
      if (!current || sha256Json(current.item) !== sha256Json(item)) throw new Error("最新情报/DQ 已变更或不放行；停止本批，不绕过隔离");
      const parents = await store.readLineage(current.verdict_event.trace_id, 0, 100000);
      const dqParent = parents.find(record => record.causation_id === current.verdict_event.event_id && ["ingest.dq1", "ingest.page_dq1"].includes(record.stage));
      const fallbackEvents: FallbackEvent[] = [];
      const results = await runEnrichment([item], {
        offline, bus, stateStore, traceId, ...(scope ? { dimensions: scope } : {}), causation_by_intel_id: { [item.intel_id]: current.intel_event.event_id },
        ...(dqParent ? { lineage_parent_by_intel_id: { [item.intel_id]: dqParent.lineage_id } } : {}), onDegrade: event => { fallbackEvents.push(event); }, ...(paperReviewer ? { paperReviewer } : {}), ...(paperReviewerProvider ? { paperReviewerProvider } : {}),
        onPaperReview: (intelId, outcome) => console.log(JSON.stringify({ type: "f1_paper_advisory", provider: outcome.provider ?? paperReviewerProvider ?? "stepplan", intel_id: intelId, status: outcome.status, ...(outcome.status === "suggested" ? { paper_ids: outcome.paper_ids, model_confidence: outcome.confidence, ...(outcome.probabilities ? { probabilities: outcome.probabilities } : {}) } : { reason: outcome.reason }), applied: false })),
      });
      processed += 1;
      if (pendingIds.has(item.intel_id)) newlyProcessed += 1;
      consecutiveArxivFailures = nextArxivFailureStreak(consecutiveArxivFailures, fallbackEvents);
      const dimensionStates = ["paper", "cvss", "epss"].map(dimension => { const state = stateStore.get(item.intel_id, dimension as "paper"); return state ? { dimension, status: state.status, reason: state.reason.slice(0, 120) } : { dimension, status: "unknown", reason: "no sidecar state" }; });
      console.log(JSON.stringify({ type: "enrichment_item", intel_id: item.intel_id, processed, dimensions_completed: results[0]?.dimensions_completed, dimensions_failed: results[0]?.dimensions_failed, dimension_states: dimensionStates, fallback_triggers: fallbackEvents.map(event => event.trigger) }));
      if (!offline && consecutiveArxivFailures >= stopAfter) {
        stoppedForSourceFailure = true;
        process.exitCode = 2;
        console.error("arXiv 连续失败，停止本批；已落库的降级记录保留，剩余条目未处理。请待来源恢复后续跑，不将降级记录算真实成功。");
        break;
      }
    }
    const afterSnapshot = readIntelIndexSnapshot(dbPath);
    const afterReceipts = publishedEnrichments(reader);
    const afterPlan = planPendingEnrichment([...afterSnapshot.accepted.values()].map(entry => entry.item), [...afterSnapshot.accepted.values()].map(entry => entry.verdict), afterReceipts.map(receipt => receipt.payload), { states: stateStore.list(), publishedEnrichments: afterReceipts, currentIntelEventIds: new Map([...afterSnapshot.accepted].map(([id, entry]) => [id, entry.intel_event.event_id])) });
    console.log(JSON.stringify({ completed_this_batch: processed, newly_recorded_this_batch: newlyProcessed, pending_after_batch: afterPlan.pending.length, real_live_dimensions: afterPlan.real_live_dimensions, stopped_for_source_failure: stoppedForSourceFailure, mode: offline ? "fixture/offline" : "live", trace_id: traceId }));
  } finally {
    if (previousOfflineFixtures === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = previousOfflineFixtures;
    contextStore?.close();
    stateStore.close();
    reader.close();
    store?.close();
    releaseLease?.();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
