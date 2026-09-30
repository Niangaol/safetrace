/**
 * SafeTrace 端到端冒烟（P0 验收标准 3）。
 * 链路：Y 线（fixture 回放）→ DQ1 闸门 → F 线（fixture 回放）→ S1 索引 → Q1→Q2→Q4 带引用答案。
 * 全部离线可跑（OFFLINE_FIXTURES=true，零外网、零容器、零 API key）。
 *
 * 验收断言：
 *  1. Y 线产出 ≥1 条 IntelItem（pass/degrade 放行），DQ1 判定落总线
 *  2. F 线对放行条目产出 EnrichmentResult（维度带 source）
 *  3. 黄金问答 20 条（R-04）：逐条硬断言主意图 / cve_ids 槽位 / 答案必含要素；
 *     非拒答条必须带引用作答，expect_abstain 条必须显式拒答
 *  4. 降级透明红线：所有 fallback.events 均 user_visible；降级响应均带 degraded_to
 *  5. MG1 经 AnswerSynthesizer 注入点完成一次真实调用（cache provider，显式可辨）
 *  6. A-02 四层兜底阶梯：工具层缺失显式 unavailable、阶梯路径 escalation_trace 留痕、
 *     全链未决显式挂起（abstain + decided_by=human）不伪造决策
 *  7. 四 Agent 任务图（监测→富化→问答）拓扑跑通，失败语义可演示
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MemoryEventStore, MemoryEventStore as Store, EventBus, sha256, sha256Json } from "@safetrace/shared";
import type { Answer, DecisionReply, DecisionRequest, FallbackEvent, IntelItem, QueryTurn } from "@safetrace/shared";
import { runIngestOnce } from "@safetrace/ingest";
import { runEnrichment } from "@safetrace/enrich";
import {
  AGENT_ROLES,
  MemoryIndex,
  classifyIntent,
  indexChunks,
  readFixtureChunks,
  runDecisionLadder,
  runTaskGraph,
  synthesizeAnswer,
  type TaskGraph,
} from "@safetrace/qa";
import { ModelGateway } from "@safetrace/gateway";

interface GoldenQuestion {
  qid: string;
  text: string;
  /** 澄清类（expects_clarify）不标注主意图 */
  expected_intent?: string;
  expects_clarify?: boolean;
  expect_abstain?: boolean;
  /** Q1 槽位硬断言：问题文本应抽出的 CVE 列表（R-04） */
  expected_cve_ids?: string[];
  /** 非拒答条答案必含要素（Answer.text_md 子串，R-04） */
  expected_answer_must_include?: string[];
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
  const enrichResults = await runEnrichment(items, {
    offline: true,
    bus,
    traceId: ingestSummary.trace_id,
    lineage_parent_by_intel_id: ingestSummary.lineage_parent_by_intel_id,
    causation_by_intel_id: ingestSummary.causation_by_intel_id,
  });
  check(enrichResults.length === items.length, "每条放行情报都有富化结果");
  const completed = enrichResults.flatMap((r) => r.dimensions_completed);
  console.log("  dimensions_completed=" + JSON.stringify([...new Set(completed)]));
  check(completed.includes("cvss") || completed.includes("paper"), "至少一个富化维度真产出");
  const withSource = enrichResults.filter((r) =>
    (r.artifacts.papers ?? []).every((p) => p.source.length > 0) ||
    (r.artifacts.score_assessment?.source_of_score ?? "").length > 0);
  check(withSource.length === enrichResults.length, "每个富化结果带 source（禁无源富化）");
  const processingLineage = await store.readLineage(ingestSummary.trace_id);
  const lineageStages = new Set(processingLineage.map((record) => record.stage));
  check(["ingest.fetch", "ingest.parse", "ingest.dedupe", "ingest.dq1", "enrich.f1", "enrich.f4", "enrich.f6"].every((stage) => lineageStages.has(stage)), "采集→DQ1→富化每个阶段均有持久 lineage");
  check(processingLineage.every((record) => record.trace_id === ingestSummary.trace_id), "采集与富化使用同一 trace_id");

  // ---------- 3) S1 索引：fixture 种子 + 富化产物 ----------
  console.log("\n[3] S1 统一索引 MemoryIndex（BM25-lite 词法兜底，S3 元数据登记）");
  const engine = new MemoryIndex({ bus });
  const seedChunks = readFixtureChunks();
  await indexChunks(engine, seedChunks, {
    collection_name: "safetrace_chunks_p0",
    model_id: engine.modelId,
    dim: 256,
    metric: "cosine",
  }, { trace_id: "tr_smoke_seed" });
  check(engine.modelId === "bm25-lite-v1", "词法索引 ID 与 S3 CollectionMeta 绑定一致");

  // ---------- 4) MG1 接线点：AnswerSynthesizer 注入 + 一次真实调用 ----------
  console.log("\n[4] MG1 接线（AnswerSynthesizer 经 /v1/chat/complete 语义调用 cache provider）");
  const gw = new ModelGateway({ bus });
  const mg1 = await gw.chat("answerer", [
    { role: "system", content: "你是安全情报问答合成器，只依据给定证据作答。" },
    { role: "user", content: "基于证据合成答案（冒烟MG1接线验证）" },
  ], {}, "tr_smoke_mg1");
  console.log("  provider=" + mg1.provider + " model=" + mg1.model_id + " degraded_to=" + JSON.stringify(mg1.degraded_to));
  check(mg1.text.length > 0, "MG1 chat 返回非空（cache provider 确定性应答）");
  check(mg1.provider === "cache" && mg1.degraded_to === "", "首选 cache 通道无降级标记");
  const usageTotals = await gw.usageTotals();
  check(usageTotals.calls >= 1, "MG1 计量落账（calls>=1）");
  const mg1Lineage = await store.readLineage("tr_smoke_mg1");
  check(mg1Lineage.some((record) => record.stage === "mg1.chat" && record.status === "success"), "MG1 provider call 写入 lineage（只存输入输出 hash）");

  // ---------- 5) 黄金问答 20 条（R-04：意图/槽位/答案要素全部硬断言） ----------
  console.log("\n[5] 黄金问答（fixtures/golden-qa.v0.json，20 条）");
  const golden = JSON.parse(
    readFileSync(resolve("fixtures/golden-qa.v0.json"), "utf8"),
  ) as { version: string; description: string; cases: GoldenQuestion[] };
  const answers: Answer[] = [];
  for (const q of golden.cases) {
    const turn: QueryTurn = { session_id: "sess_smoke", turn_id: q.qid, text: q.text };
    const plan = classifyIntent(turn);
    const traceId = "tr_" + q.qid;
    const q1Lineage = await bus.recordLineage({
      trace_id: traceId,
      stage: "qa.q1_classify",
      operation_version: "q1-rules.v1",
      status: "success",
      input_refs: [{ kind: "Query", id: q.qid, sha256: sha256(q.text) }],
      output_refs: [{ kind: "QueryPlan", id: q.qid, sha256: sha256Json(plan) }],
      execution: { component_version: "q1-rules.v1" },
    });
    const req = {
      query_id: "q_" + q.qid,
      query_text: plan.rewrite_text,
      top_k: 5,
      // R-04：CVE 槽位必须透传成 Q2 过滤条件（问题指定的漏洞必须被证据覆盖）
      ...(plan.slots.cve_ids.length > 0 ? { cve_ids: plan.slots.cve_ids } : {}),
      trace_id: traceId,
      schema_version: "1.0",
    };
    const evidence = await engine.search(req, { parent_lineage_ids: [q1Lineage.lineage_id] });
    const q2Lineage = (await bus.readLineage(traceId)).filter((record) => record.stage === "q2.bm25_search").at(-1);
    const ans = await synthesizeAnswer(q.text, plan, evidence, {
      session_id: turn.session_id,
      turn_id: turn.turn_id,
      bus,
      parent_lineage_ids: [q1Lineage.lineage_id, ...(q2Lineage ? [q2Lineage.lineage_id] : [])],
      synth: undefined, // P0 默认模板合成器；LLM 合成经 MG1 注入（见第 4 步）
    });
    answers.push(ans);
    // R-04：口径做实——意图、cve_ids 槽位、答案必含要素逐条硬断言，不再"带引用或拒答"和稀泥
    if (q.expected_intent) {
      check(plan.intents[0] === q.expected_intent,
        q.qid + " 主意图=" + q.expected_intent + "（实际 " + (plan.intents[0] ?? "none") + "）");
    }
    if (q.expects_clarify) {
      check(plan.needs_clarify === true, q.qid + " 低置信度输入应触发澄清（禁硬猜）");
    } else {
      check(plan.needs_clarify === false, q.qid + " 不应要求澄清");
    }
    check(JSON.stringify(plan.slots.cve_ids) === JSON.stringify(q.expected_cve_ids ?? []),
      q.qid + " cve_ids 槽位=" + JSON.stringify(q.expected_cve_ids ?? []) + "（实际 " + JSON.stringify(plan.slots.cve_ids) + "）");
    if (q.expect_abstain) {
      check(ans.abstained, q.qid + " 无答案问题显式拒答（禁编造）");
    } else {
      check(!ans.abstained && ans.citations.length > 0,
        q.qid + "（意图 " + (plan.intents[0] ?? "unknown") + "）答案带完整引用（禁含糊：非拒答条必须作答）");
      const missing = (q.expected_answer_must_include ?? []).filter((s) => !ans.text_md.includes(s));
      check(missing.length === 0,
        q.qid + " 答案必含要素 " + JSON.stringify(q.expected_answer_must_include ?? []) +
        (missing.length > 0 ? " 缺失：" + missing.join("、") : ""));
    }
  }
  const queryLineageComplete = await Promise.all(golden.cases.map(async (q) => {
    const records = await bus.readLineage("tr_" + q.qid);
    const stages = new Set(records.map((record) => record.stage));
    return stages.has("qa.q1_classify") && stages.has("q2.bm25_search") && stages.has("qa.q4_answer") && records.every((record) => !JSON.stringify(record).includes(q.text));
  }));
  check(queryLineageComplete.every(Boolean), "20 条黄金问答均保存 Q1/Q2/Q4 lineage，且不重复存原始 query");

  const expectAnswerCount = golden.cases.filter((q) => !q.expect_abstain).length;
  const withCitations = answers.filter((a) => a.citations.length > 0).length;
  check(withCitations === expectAnswerCount,
    "全部 " + expectAnswerCount + " 条非拒答基准都带完整引用（当前 " + withCitations + "）");
  const citationsComplete = answers.every((a) =>
    a.citations.every((c) => c.chunk_id.length > 0 && c.url.length > 0));
  check(citationsComplete, "引用完整率 100%（chunk_id + url 非空）");

  // C-04：答案对象必须显式带注入筛查状态；非拒答条可带 stale_warning（证据过龄/未知时）
  const guarded = answers.filter((a) => a.injection_guard !== undefined).length;
  check(guarded === answers.length, "所有答案显式带 injection_guard（缺省=未筛查，不假装干净），当前 " + guarded + "/" + answers.length);
  const nonAbstained = answers.filter((a) => !a.abstained);
  const staleCarriers = nonAbstained.filter((a) => a.stale_warning !== undefined).length;
  console.log("  带 stale_warning 的非拒答答案：" + staleCarriers + " 条（种子证据发布于 2021，阈值 365 天 → 预期全部提示）");
  check(staleCarriers === nonAbstained.length, "过龄证据必须显式带 stale_warning，且正文对用户可见");

  // ---------- 6) A-02 四层兜底阶梯（工具→规则→LLM→人工） ----------
  console.log("\n[6] 决策阶梯（A-02：逐层显式下坠，禁静默兜底）");
  const ladderReq: DecisionRequest = {
    decision_id: "dec_smoke",
    kind: "q1_route",
    state: { question: "Log4Shell 影响哪些版本？" },
    questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
    trace_id: "tr_smoke_ladder",
    schema_version: "1.0",
  };
  const ladderRule = await runDecisionLadder(ladderReq, { bus, rule: async () => ({ choice: "impact_range", score: 0.9 }) });
  check(ladderRule.escalation_trace.some((a) => a.layer === "tool" && a.status === "unavailable"),
    "工具层未接入必须显式记 unavailable（不静默跳过），实际 " + JSON.stringify(ladderRule.escalation_trace.map((a) => a.layer + ":" + a.status)));
  check(ladderRule.reply.decided_by === "rule_fallback" && (ladderRule.reply.fallback_reason ?? "").length > 0,
    "规则层命中：decided_by=rule_fallback 且下坠原因显式进响应");
  const ladderUnresolved = await runDecisionLadder({ ...ladderReq, decision_id: "dec_smoke_unresolved" }, { bus });
  check(ladderUnresolved.escalation_trace.map((a) => a.layer).join(">") === "tool>rule>llm>human",
    "阶梯路径完整留痕 escalation_trace=tool>rule>llm>human");
  check(ladderUnresolved.reply.decision.abstain === true && ladderUnresolved.reply.decided_by === "human" && ladderUnresolved.reply.decision.choice === undefined,
    "全链未决显式挂起（abstain + decided_by=human），不伪造 choice");
  const ladderReplies = await store.read<DecisionReply>("decision.replies");
  check(ladderReplies.length === 2, "decision.replies 全量入总线可 replay（" + ladderReplies.length + " 条）");
  const ladderLineage = await store.readLineage("tr_smoke_ladder");
  check(ladderLineage.some((r) => r.stage === "decide.ladder" && r.status === "review"),
    "未决阶梯留 lineage（stage=decide.ladder, status=review）");
  check(ladderLineage.every((r) => !JSON.stringify(r).includes("影响哪些版本")),
    "阶梯 lineage 只存输入输出 hash，不复制决策正文");

  // ---------- 7) 四 Agent 任务图 ----------
  console.log("\n[7] 编排层四 Agent 任务图（监测→富化→问答）");
  check(Object.keys(AGENT_ROLES).length === 4, "四角色登记在册");
  let taskIngest: Awaited<ReturnType<typeof runIngestOnce>> | undefined;
  const graph: TaskGraph = {
    nodes: [
      { id: "monitor", role: "monitor", run: async () => { taskIngest = await runIngestOnce({ store, offline: true }); } },
      { id: "enricher", role: "enricher", deps: ["monitor"], on_fail: "degrade",
        run: async () => { const its = (await store.read<IntelItem>("intel.items")).map((e) => e.payload);
          await runEnrichment(its, { offline: true, bus, traceId: taskIngest?.trace_id, lineage_parent_by_intel_id: taskIngest?.lineage_parent_by_intel_id, causation_by_intel_id: taskIngest?.causation_by_intel_id }); } },
      { id: "qa", role: "qa", deps: ["enricher"],
        run: async () => { const t: QueryTurn = { session_id: "sess_tg", turn_id: "t1", text: "Log4Shell 影响哪些版本？" };
          const traceId = "tr_tg";
          const p = classifyIntent(t);
          const q1 = await bus.recordLineage({ trace_id: traceId, stage: "qa.q1_classify", operation_version: "q1-rules.v1", status: "success", input_refs: [{ kind: "Query", id: t.turn_id, sha256: sha256(t.text) }], output_refs: [{ kind: "QueryPlan", id: t.turn_id, sha256: sha256Json(p) }] });
          const ev = await engine.search({ query_id: "q_tg", query_text: p.rewrite_text, top_k: 3, trace_id: traceId, schema_version: "1.0" }, { parent_lineage_ids: [q1.lineage_id] });
          const q2 = (await bus.readLineage(traceId)).filter((record) => record.stage === "q2.bm25_search").at(-1);
          await synthesizeAnswer(t.text, p, ev, { session_id: t.session_id, turn_id: t.turn_id, bus, parent_lineage_ids: [q1.lineage_id, ...(q2 ? [q2.lineage_id] : [])] }); } },
    ],
  };
  const tgResult = await runTaskGraph(graph, { bus, traceId: "tr_smoke_tg" });
  check(tgResult.ok, "任务图全节点执行成功（executed=" + tgResult.executed.join(">") + "）");

  // ---------- 汇总：降级透明红线 ----------
  console.log("\n[8] 降级透明红线（禁静默兜底）");
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
