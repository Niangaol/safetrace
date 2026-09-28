/**
 * CLI 入口：npx tsx src/qa/src/cli.ts "Log4Shell 影响哪些版本？怎么修复？"
 * 全链路：种子 MemoryIndex → Q1 意图 → Q2 检索 → Q4 四段式答案（含引用角标与置信度）。
 */
import { pathToFileURL } from "node:url";
import { nextId } from "@safetrace/shared";
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
export async function ask(question: string, opts: { session_id?: string; turn_id?: string } = {}): Promise<Answer> {
  const traceId = nextId("tr");
  const turn: QueryTurn = {
    session_id: opts.session_id ?? nextId("sess"),
    turn_id: opts.turn_id ?? nextId("turn"),
    text: question,
  };
  const plan = classifyIntent(turn);
  const engine = new MemoryIndex();
  await indexChunks(engine, readFixtureChunks(), {
    collection_name: SEED_COLLECTION,
    model_id: engine.modelId,
    dim: 256,
    metric: "cosine",
  });
  const evidence = await engine.search(buildRetrievalRequest(turn.text, plan, traceId));
  return synthesizeAnswer(turn.text, plan, evidence, { session_id: turn.session_id, turn_id: turn.turn_id });
}

function isMainEntry(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isMainEntry()) {
  const question = process.argv.slice(2).join(" ").trim() || "Log4Shell 影响哪些版本？怎么修复？";
  ask(question)
    .then((ans) => {
      console.log(ans.text_md);
      if (ans.abstained) console.log("\n（abstained：证据不足，已按项目红线拒答，未编造内容）");
    })
    .catch((err: unknown) => {
      console.error("CLI 失败：" + (err instanceof Error ? err.message : String(err)));
      process.exitCode = 1;
    });
}
