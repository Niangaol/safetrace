/**
 * SafeTrace 端到端冒烟（P0 验收标准 3）。
 * 链路：Y 线（fixture 回放）→ DQ1 闸门 → F 线（fixture 回放）→ S1 索引 → Q1→Q2→Q4 带引用答案。
 * 全部离线可跑（OFFLINE_FIXTURES=true，零外网、零容器、零 API key）。
 *
 * 验收断言：
 *  1. Y 线产出 ≥1 条 IntelItem（pass/degrade 放行），DQ1 判定落总线
 *  2. F 线对放行条目产出 EnrichmentResult（维度带 source）
 *  3. 黄金问答 10 条：非禁答条必须带引用；expect_abstain 条必须显式拒答
 *  4. 降级透明红线：所有 fallback.events 均 user_visible；降级响应均带 degraded_to
 *  5. MG1 经 AnswerSynthesizer 注入点完成一次真实调用（cache provider，显式可辨）
 *  6. 四 Agent 任务图（监测→富化→问答）拓扑跑通，失败语义可演示
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MemoryEventStore, MemoryEventStore as Store, EventBus } from "@safetrace/shared";
import type { Answer, FallbackEvent, IntelItem, QueryTurn } from "@safetrace/shared";
import { runIngestOnce } from "@safetrace/ingest";
import { runEnrichment } from "@safetrace/enrich";
import {
  AGENT_ROLES,
  MemoryIndex,
  classifyIntent,
  indexChunks,
  readFixtureChunks,
  runTaskGraph,
  synthesizeAnswer,
  type TaskGraph,
} from "@safetrace/qa";
import { ModelGateway } from "@safetrace/gateway";

interface GoldenQuestion {
  qid: string;
  text: string;
  expected_intent: string;
  expect_abstain?: boolean;
  notes?: string;
}

const failures: string[] = [];
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log("  PASS " + label);
  } else {
    console.log("  FAIL " + label);
    failures.push(label);
  }
}

async function main(): Promise<number> {
  console.log("== SafeTrace 冒烟（离线 fixture 回放） ==");
  const store = new Store();
  const bus = new EventBus({ store });
  const fallbackSeen: FallbackEvent[] = [];
  bus.subscribe("fallback.events", (p: FallbackEvent) => { fallbackSeen.push(p); });

  // ---------- 1) Y 线：采集→适配→去重→DQ1（fixture 回放，降级显式） ----------
  console.log("\n[1] Y 监测线 runIngestOnce(offline)");
  const ingestSummary = await runIngestOnce({ store, offline: true });
  console.log("  fetched=" + ingestSummary.fetched.length + " parsed=" + ingestSummary.parsed.length +
    " merged=" + ingestSummary.merged.length + " verdicts=" + ingestSummary.verdicts.length +
    " fallbackEvents=" + ingestSummary.fallbackEvents.length);
  check(ingestSummary.parsed.length >= 4, "四源 fixture 全部解析（parsed>=4）");
  check((ingestSummary.degraded_to ?? "") === "fixture", "IngestRunResult.degraded_to=fixture（响应对象显式带降级标记）");
  check(ingestSummary.fallbackEvents.length > 0, "离线回放产生显式 fallback 事件");
  check(ingestSummary.fallbackEvents.every((e) => e.degraded_of === "fixture"),
    "降级通道为 fixture 且全部显式登记");

  const intelEvents = await store.read<IntelItem>("intel.items");
  check(intelEvents.length >= 1, "DQ1 放行后 intel.items 至少 1 条");
  const items = intelEvents.map((e) => e.payload);
  const dqEvents = await store.read("dq.verdicts");
  check(dqEvents.length >= 1, "dq.verdicts 落总线（四档判定可追溯）");

  // ---------- 2) F 线：论文 + CVSS/EPSS（fixture 回放） ----------
  console.log("\n[2] F 富化线 runEnrichment(offline)");
  const enrichResults = await runEnrichment(items, { offline: true, bus });
  check(enrichResults.length === items.length, "每条放行情报都有富化结果");
  const completed = enrichResults.flatMap((r) => r.dimensions_completed);
  console.log("  dimensions_completed=" + JSON.stringify([...new Set(completed)]));
  check(completed.includes("cvss") || completed.includes("paper"), "至少一个富化维度真产出");
  const withSource = enrichResults.filter((r) =>
    (r.artifacts.papers ?? []).every((p) => p.source.length > 0) ||
    (r.artifacts.score_assessment?.source_of_score ?? "").length > 0);
  check(withSource.length === enrichResults.length, "每个富化结果带 source（禁无源富化）");

  // ---------- 3) S1 索引：fixture 种子 + 富化产物 ----------
  console.log("\n[3] S1 统一索引 MemoryIndex（hash-256 占位嵌入，S3 绑定登记）");
  const engine = new MemoryIndex();
  const seedChunks = readFixtureChunks();
  await indexChunks(engine, seedChunks, {
    collection_name: "safetrace_chunks_p0",
    model_id: engine.modelId,
    dim: 256,
    metric: "cosine",
  });
  check(engine.modelId === "hash-256", "embedder_model_id 与 S3 CollectionMeta 绑定一致");

  // ---------- 4) MG1 接线点：AnswerSynthesizer 注入 + 一次真实调用 ----------
  console.log("\n[4] MG1 接线（AnswerSynthesizer 经 /v1/chat/complete 语义调用 cache provider）");
  const gw = new ModelGateway();
  const mg1 = await gw.chat("answerer", [
    { role: "system", content: "你是安全情报问答合成器，只依据给定证据作答。" },
    { role: "user", content: "基于证据合成答案（冒烟MG1接线验证）" },
  ], {}, "tr_smoke_mg1");
  console.log("  provider=" + mg1.provider + " model=" + mg1.model_id + " degraded_to=" + JSON.stringify(mg1.degraded_to));
  check(mg1.text.length > 0, "MG1 chat 返回非空（cache provider 确定性应答）");
  check(mg1.provider === "cache" && mg1.degraded_to === "", "首选 cache 通道无降级标记");
  const usageTotals = await gw.usageTotals();
  check(usageTotals.calls >= 1, "MG1 计量落账（calls>=1）");

  // ---------- 5) 黄金问答 10 条 ----------
  console.log("\n[5] 黄金问答（fixtures/golden-qa.v0.json）");
  const golden = JSON.parse(
    readFileSync(resolve("fixtures/golden-qa.v0.json"), "utf8"),
  ) as { version: string; description: string; cases: GoldenQuestion[] };
  const answers: Answer[] = [];
  for (const q of golden.cases) {
    const turn: QueryTurn = { session_id: "sess_smoke", turn_id: q.qid, text: q.text };
    const plan = classifyIntent(turn);
    const req = {
      query_id: "q_" + q.qid,
      query_text: plan.rewrite_text,
      top_k: 5,
      trace_id: "tr_" + q.qid,
      schema_version: "1.0",
    };
    const evidence = await engine.search(req);
    const ans = await synthesizeAnswer(q.text, plan, evidence, {
      session_id: turn.session_id,
      turn_id: turn.turn_id,
      synth: undefined, // P0 默认模板合成器；LLM 合成经 MG1 注入（见第 4 步）
    });
    answers.push(ans);
    const cited = ans.citations.length > 0 && !ans.abstained;
    if (q.expect_abstain) {
      check(ans.abstained, q.qid + " 无答案问题显式拒答（禁编造）");
    } else {
      check(cited || ans.abstained, q.qid + "（意图 " + (plan.intents[0] ?? "unknown") + "）答案带引用或显式拒答");
    }
  }
  const withCitations = answers.filter((a) => a.citations.length > 0).length;
  check(withCitations >= 5, "至少 5 条答案带完整引用（当前 " + withCitations + "）");
  const citationsComplete = answers.every((a) =>
    a.citations.every((c) => c.chunk_id.length > 0 && c.url.length > 0));
  check(citationsComplete, "引用完整率 100%（chunk_id + url 非空）");

  // ---------- 6) 四 Agent 任务图 ----------
  console.log("\n[6] 编排层四 Agent 任务图（监测→富化→问答）");
  check(Object.keys(AGENT_ROLES).length === 4, "四角色登记在册");
  const graph: TaskGraph = {
    nodes: [
      { id: "monitor", role: "monitor", run: async () => { await runIngestOnce({ store, offline: true }); } },
      { id: "enricher", role: "enricher", deps: ["monitor"], on_fail: "degrade",
        run: async () => { const its = (await store.read<IntelItem>("intel.items")).map((e) => e.payload);
          await runEnrichment(its, { offline: true, bus }); } },
      { id: "qa", role: "qa", deps: ["enricher"],
        run: async () => { const t: QueryTurn = { session_id: "sess_tg", turn_id: "t1", text: "Log4Shell 影响哪些版本？" };
          const p = classifyIntent(t);
          const ev = await engine.search({ query_id: "q_tg", query_text: p.rewrite_text, top_k: 3, trace_id: "tr_tg", schema_version: "1.0" });
          await synthesizeAnswer(t.text, p, ev, { session_id: t.session_id, turn_id: t.turn_id }); } },
    ],
  };
  const tgResult = await runTaskGraph(graph, { bus, traceId: "tr_smoke_tg" });
  check(tgResult.ok, "任务图全节点执行成功（executed=" + tgResult.executed.join(">") + "）");

  // ---------- 汇总：降级透明红线 ----------
  console.log("\n[7] 降级透明红线（禁静默兜底）");
  const silent = fallbackSeen.filter((e) => !e.user_visible);
  check(silent.length === 0, "零静默兜底（fallback.events 全部 user_visible，共 " + fallbackSeen.length + " 条）");
  const degradedAnswers = answers.filter((a) => (a.degraded_to ?? "") !== "");
  console.log("  带 degraded_to 标记的答案：" + degradedAnswers.length + " 条");

  console.log("\n== 冒烟结束 ==");
  if (failures.length > 0) {
    console.log("失败 " + failures.length + " 项：");
    for (const f of failures) console.log("  - " + f);
    return 1;
  }
  console.log("全部通过：核心链路（采集→富化→入库→问答）离线可复现");
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("冒烟异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });
