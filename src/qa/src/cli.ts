/**
 * CLI 入口：npx tsx src/qa/src/cli.ts "Log4Shell 影响哪些版本？怎么修复？"
 * 全链路：种子 MemoryIndex → Q1 意图 → Q2 检索 → Q4 四段式答案（含引用角标与置信度）。
 */
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { EventBus, nextId, nowIso, sha256, sha256Json, SqliteEventStore } from "@safetrace/shared";
import type { Answer, QueryTurn, RetrievalRequest } from "@safetrace/shared";
import { classifyIntent } from "./q1-intent.js";
import type { QueryPlan } from "./q1-intent.js";
import { MemoryIndex, indexChunks, readFixtureChunks } from "./q2-retrieval.js";
import { synthesizeAnswer } from "./q4-answer.js";

const SEED_COLLECTION = "safetrace_chunks_p0";

/** Q1 槽位 → Q2 请求：CVE 槽位转 cve_ids 过滤（问题指定的漏洞必须被证据覆盖）。 */
export function buildRetrievalRequest(question: string, plan: QueryPlan, traceId: string): RetrievalRequest {
  return {
    query_id: nextId("q"),
    query_text: plan.rewrite_text,
    top_k: 5,
    ...(plan.slots.cve_ids.length > 0 ? { cve_ids: plan.slots.cve_ids } : {}),
    trace_id: traceId,
    schema_version: "1.0",
  };
}

/** 全链路（CLI / 冒烟脚本共用）。 */
export async function ask(
  question: string,
  opts: { session_id?: string; turn_id?: string; trace_id?: string; bus?: EventBus } = {},
): Promise<Answer> {
  const traceId = opts.trace_id ?? nextId("tr");
  const turn: QueryTurn = {
    session_id: opts.session_id ?? nextId("sess"),
    turn_id: opts.turn_id ?? nextId("turn"),
    text: question,
  };
  const q1Started = nowIso();
  const plan = classifyIntent(turn);
  const q1Lineage = await opts.bus?.recordLineage({
    trace_id: traceId,
    stage: "qa.q1_classify",
    operation_version: "q1-rules.v1",
    status: "success",
    started_at: q1Started,
    input_refs: [{ kind: "Query", id: turn.turn_id, sha256: sha256(question) }],
    output_refs: [{ kind: "QueryPlan", id: turn.turn_id, sha256: sha256Json(plan) }],
    execution: { component_version: "q1-rules.v1" },
  });
  const engine = new MemoryIndex({ bus: opts.bus });
  await indexChunks(engine, readFixtureChunks(), {
    collection_name: SEED_COLLECTION,
    model_id: engine.modelId,
    dim: 256,
    metric: "cosine",
  }, { trace_id: traceId });
  const request = buildRetrievalRequest(turn.text, plan, traceId);
  const evidence = await engine.search(request, {
    ...(q1Lineage ? { parent_lineage_ids: [q1Lineage.lineage_id] } : {}),
  });
  const traceRows = opts.bus ? await opts.bus.readLineage(traceId) : [];
  const q2Lineage = traceRows.filter((row) => row.stage === "q2.bm25_search").at(-1);
  return synthesizeAnswer(turn.text, plan, evidence, {
    session_id: turn.session_id,
    turn_id: turn.turn_id,
    bus: opts.bus,
    parent_lineage_ids: [q1Lineage?.lineage_id, q2Lineage?.lineage_id].filter((id): id is string => Boolean(id)),
  });
}

function isMainEntry(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isMainEntry()) {
  const question = process.argv.slice(2).join(" ").trim() || "Log4Shell 影响哪些版本？怎么修复？";
  const traceId = nextId("tr");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  void mkdir(dirname(dbPath), { recursive: true }).then(async () => {
    const store = new SqliteEventStore(dbPath);
    const bus = new EventBus({ store });
    try {
      const ans = await ask(question, { bus, trace_id: traceId });
      console.log("trace_id=" + traceId);
      console.log(ans.text_md);
      if (ans.abstained) console.log("\n（abstained：证据不足，已按项目红线拒答，未编造内容）");
    } catch (err) {
      console.error("CLI 失败：" + (err instanceof Error ? err.message : String(err)));
      process.exitCode = 1;
    } finally {
      store.close();
    }
  }).catch((err: unknown) => {
    console.error("CLI 启动失败：" + (err instanceof Error ? err.message : String(err)));
    process.exitCode = 1;
  });
}
