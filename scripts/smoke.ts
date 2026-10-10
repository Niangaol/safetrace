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
 *     全链未决显式挂起（abstain + decided_by=human）不伪造决策；
 *     A-03 数据隔离：默认配置 private 角色仍由本机通道服务，闸门不误伤
 *  7. 四 Agent 任务图（监测→富化→问答）拓扑跑通，失败语义可演示
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MemoryEventStore, MemoryEventStore as Store, EventBus, degrade, nowIso, sha256, sha256Json } from "@safetrace/shared";
import type { Answer, DecisionReply, DecisionRequest, FallbackEvent, IntelItem, QueryTurn } from "@safetrace/shared";
import type { MachineSpec } from "@safetrace/qa";
import { runIngestOnce } from "@safetrace/ingest";
import { runEnrichment } from "@safetrace/enrich";
import {
  AGENT_ROLES,
  MemoryIndex,
  SelfHealAgent,
  SelfHealDaemon,
  answerVersionImpact,
  claimHumanTicket,
  classifyIntent,
  resolveHumanTicket,
  resumeMachine,
  runDecisionLadder,
  runMachine,
  indexChunks,
  readFixtureChunks,
  runTaskGraph,
  synthesizeAnswer,
  type TaskGraph,
} from "@safetrace/qa";
import { ModelGateway } from "@safetrace/gateway";
import { buildRetrievalRequest } from "../src/qa/src/cli.js";
import { staleThresholdDays } from "../src/qa/src/q1-intent.js";

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
      // 版本题通过同一确定性规则入口，不能以旧模板自由摘录代替版本判定。
      ...(plan.slots.products.length === 1 && plan.slots.versions.length === 1 && plan.slots.cve_ids.length <= 1 ? {
        version_impact: answerVersionImpact(items, { product: plan.slots.products[0]!, version: plan.slots.versions[0]!, ...(plan.slots.cve_ids.length ? {cve_id: plan.slots.cve_ids[0]} : {}) }),
      } : {}),
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
  console.log("\n[6] 决策阶梯（A-02）与数据隔离闸门抽检（A-03）");
  // A-03：默认配置下 private 角色（decision）仍由本机 cache 通道服务，隔离闸门不得误伤本机通道
  const decisionPrivate = await gw.chat("decision", [{ role: "user", content: "y5 triage" }], {}, "tr_smoke_isolation");
  check(decisionPrivate.provider === "cache" && (decisionPrivate.degraded_to ?? "") === "",
    "默认配置 private 角色由本机通道服务（隔离闸门不误伤 cache/local）");
  const isolationRows = await store.readLineage("tr_smoke_isolation");
  check(!isolationRows.some((r) => r.stage === "mg1.isolation_gate"), "本机通道不触发隔离拒绝");
  check(isolationRows.every((r) => !JSON.stringify(r).includes("y5 triage")), "隔离判定 lineage 不复制请求内容");
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

  // ---------- 9) A-06 自愈：fallback 登记 + 死信退避重投 + 健康看板 ----------
  console.log("\n[9] A1 自愈（fallback 登记 / 死信指数退避重投 / healthcheck）");
  const selfheal = new SelfHealAgent({ bus, store, backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 8 } });
  selfheal.subscribeFallbackEvents();
  // 新产生的一次显式降级必须被自愈 Agent 登记（兜底透明率 100% 的运行时证据）
  await degrade({
    layer: "L1",
    trigger: "smoke selfheal spot-check",
    degradedOf: "smoke:selfheal",
    traceId: "tr_smoke_selfheal",
    label: "冒烟自愈抽检（显式降级）",
    emit: async (event) => { await bus.publish("fallback.events", event, { trace_id: event.trace_id }); },
  });
  check(selfheal.registeredFallbackEvents.length === 1, "自愈 Agent 登记新降级事件（兜底透明率 100%）");
  check(selfheal.registeredFallbackEvents.every((e) => e.user_visible), "登记事件全部用户可见（禁静默兜底）");

  // 死信路径（模拟重启后从持久库加载的死信）：留档 → 退避窗口内不重投 → 修复后到拍重投销档
  let consumerBroken = true;
  const releaseBreak = bus.subscribe("decision.replies", async () => {
    if (consumerBroken) throw new Error("smoke: consumer temporarily broken");
  });
  const drillEventIds: string[] = [];
  for (let i = 0; i < 3; i += 1) {
    const reply: DecisionReply = {
      decision_id: "dec_smoke_selfheal_" + i,
      kind: "q1_route",
      decision: { choice: "impact_range" },
      calibrated_prob: 0.9,
      decided_by: "rule_fallback",
      schema_version: "1.0",
    };
    const env = await bus.publish("decision.replies", reply, { trace_id: "tr_smoke_selfheal_dl" });
    drillEventIds.push(env.event_id);
    // 等价于总线重试耗尽后的落库结果（真实路径由 EventBus.deliver 超过 maxRetries 触发）
    await store.markDeadLetter(env.event_id, "smoke: simulated exhausted retries");
  }
  const deadBefore = (await store.deadLetters()).length;
  check(deadBefore === 3, "3 条死信留档待自愈（实际 " + deadBefore + "）");
  const nowMs = 1_800_000_000_000;
  const firstDrain = await selfheal.dead_letter_drain({ now: nowMs });
  check(firstDrain.retried === 3 && firstDrain.recovered === 0,
    "首次重投 3 条全部失败（消费者仍坏，retried=" + firstDrain.retried + " recovered=" + firstDrain.recovered + "）");
  const windowDrain = await selfheal.dead_letter_drain({ now: nowMs });
  check(windowDrain.retried === 0, "指数退避窗口内不重投（retried=" + windowDrain.retried + "）");
  consumerBroken = false;
  releaseBreak();
  let replayedCount = 0;
  const releaseFix = bus.subscribe("decision.replies", async () => { replayedCount += 1; });
  const drain = await selfheal.dead_letter_drain({ now: nowMs + 1500 });
  check(drain.recovered === 3, "到拍重投 3 条全部恢复（recovered=" + drain.recovered + "）");
  check(replayedCount === 3, "恢复后的消费者实际处理 3 条重放（" + replayedCount + "）");
  check((await store.deadLetters()).length === 0, "死信队列清零（销档）");
  const health = await selfheal.healthcheck();
  check(health.fallback_events.total === 1 && health.dead_letters === 0, "healthcheck 聚合死信/降级计数");
  check(health.circuits_observed === false && health.notes.some((n) => n.includes("未注入熔断探针")),
    "未注入熔断探针时显式注明（不冒充健康）");
  releaseFix();

  // ---------- 10) A-05 时效性：published_after 真过滤 + 意图时效阈值 ----------
  console.log("\n[10] A-05 时效性（published_after 真实生效 / 意图驱动过龄阈值）");
  {
    // ① 未来窗口 → 空结果：seed 为 2021 年样本，必须被时间窗滤掉（旧实现直接 return true）
    const futureWindow = await engine.search({
      query_id: "q_smoke_a05_future", query_text: "Log4Shell 影响版本 修复", top_k: 5,
      published_after: "2999-01-01T00:00:00.000Z", trace_id: "tr_smoke_a05_future", schema_version: "1.0",
    });
    check(futureWindow.chunks.length === 0, "published_after=未来 → 空结果（时效过滤真实生效，不再是 return true）");
    // ② 宽窗口 → 旧 seed 正常召回（时间过滤不误伤）
    const wideWindow = await engine.search({
      query_id: "q_smoke_a05_wide", query_text: "Log4Shell 影响版本 修复", top_k: 5,
      published_after: "1999-01-01T00:00:00.000Z", trace_id: "tr_smoke_a05_wide", schema_version: "1.0",
    });
    check(wideWindow.chunks.length > 0, "published_after=1999 → 2021 年 seed 正常召回（过滤不误伤）");
    // ③ 不可解析 → fail-closed 抛错（静默放过等于过滤失效）
    let a05Rejected = false;
    try {
      await engine.search({
        query_id: "q_smoke_a05_bad", query_text: "Log4Shell", top_k: 5,
        published_after: "昨天", trace_id: "tr_smoke_a05_bad", schema_version: "1.0",
      });
    } catch { a05Rejected = true; }
    check(a05Rejected, "published_after 不可解析 → 抛错（fail-closed，禁静默放过）");
    // ④ Q1 time_range 槽位 → published_after 硬过滤（"最近 7 天"不再只是 rewrite 后缀）
    const trendTurn: QueryTurn = { session_id: "sess_smoke_a05", turn_id: "turn_a05", text: "最近一周的漏洞趋势" };
    const trendPlan = classifyIntent(trendTurn);
    const trendReq = buildRetrievalRequest(trendTurn.text, trendPlan, "tr_smoke_a05_trend");
    check(typeof trendReq.published_after === "string" && trendPlan.slots.time_range === "7d",
      "Q1 time_range=7d 槽位转成 published_after 硬过滤（" + JSON.stringify(trendReq.published_after ?? null) + "）");
    // ⑤ 意图阈值：trend 收紧为 7 天，过龄证据显式提示且答案不拒答
    const trendEvidence = await engine.search({
      query_id: "q_smoke_a05_trend_ev", query_text: trendPlan.rewrite_text, top_k: 5,
      trace_id: "tr_smoke_a05_trend", schema_version: "1.0",
    });
    const trendAnswer = await synthesizeAnswer(trendTurn.text, trendPlan, trendEvidence, {
      session_id: trendTurn.session_id, turn_id: trendTurn.turn_id, bus,
      stale_after_days: staleThresholdDays(trendPlan),
    });
    check(trendAnswer.abstained === false && trendAnswer.stale_warning?.threshold_days === 7,
      "trend 意图阈值 7 天：过龄证据显式带 stale_warning（threshold_days=7）且正常作答");
    check(trendAnswer.text_md.includes("阈值 7 天"), "过龄提示在正文对用户可见（写明收紧后的阈值）");
  }

  // ---------- 11) P-05 来源冲突进答案（多源分歧显式保留，不压成单一结论） ----------
  console.log("\n[11] P-05 来源冲突（多源分值分歧显式保留）");
  {
    // ① 富化批量返回 outcome：内存侧带 conflicts 审计字段（总线契约仍纯净）
    check(Array.isArray(enrichResults[0]!.conflicts),
      "runEnrichment 返回 EnrichmentOutcome（内存侧带 conflicts，答案侧可消费）");
    const p05Turn: QueryTurn = { session_id: "sess_smoke_p05", turn_id: "turn_p05", text: "Log4Shell 影响哪些版本？" };
    const p05Plan = classifyIntent(p05Turn);
    const p05Evidence = await engine.search({ query_id: "q_smoke_p05", query_text: p05Plan.rewrite_text, top_k: 5, trace_id: "tr_smoke_p05", schema_version: "1.0" });
    // ② 注入一条多源冲突 → 正文 / reasoning_chain / Answer 对象三处可见
    const p05Answer = await synthesizeAnswer(p05Turn.text, p05Plan, p05Evidence, {
      session_id: p05Turn.session_id, turn_id: p05Turn.turn_id, bus,
      source_conflicts: [{ field: "cvss_v3_base", values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 8.8 }], resolved: true, rationale: "冒烟注入：采用 nvd 的 7.5 分；差异源仅作旁证" }],
    });
    check(!p05Answer.abstained && p05Answer.text_md.includes("## 来源冲突") && p05Answer.text_md.includes("nvd 7.5 vs cna 8.8"),
      "冲突段落与分歧数值进正文（不压成单一结论）");
    check(p05Answer.source_conflicts?.length === 1 && p05Answer.reasoning_chain.some((s) => s.includes("P-05 冲突保留")),
      "Answer.source_conflicts 与推理链条目齐备");
    // ③ 未提供冲突 → 不渲染段落、不设字段（缺省不当「无冲突」）
    const p05Plain = await synthesizeAnswer(p05Turn.text, p05Plan, p05Evidence, { session_id: p05Turn.session_id, turn_id: p05Turn.turn_id, bus });
    check(p05Plain.source_conflicts === undefined && !p05Plain.text_md.includes("## 来源冲突"),
      "未提供冲突时答案不渲染冲突段落（缺省语义如实）");
    // ④ 形态非法的冲突 fail-closed 抛错（不静默丢弃）
    let p05Rejected = false;
    try {
      await synthesizeAnswer(p05Turn.text, p05Plan, p05Evidence, {
        session_id: p05Turn.session_id, turn_id: p05Turn.turn_id, bus,
        source_conflicts: [{ field: "cvss_v3_base", values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 7.5 }], resolved: false }],
      });
    } catch { p05Rejected = true; }
    check(p05Rejected, "同值无分歧的冲突条目 fail-closed 抛错（不静默丢弃）");
  }

  // ---------- 12) P-03 版本影响确定性入口（规则同资产线，不进相似度/模型） ----------
  console.log("\n[12] P-03 版本影响（确定性规则判定 + 结构化查询）");
  {
    // ① 规则入口：fixture 情报（Log4j <=2.14.1 等）判定 2.14.1 受影响、区间外不能排除即 unknown
    const p03Items = (await store.read<IntelItem>("intel.items")).map((e) => e.payload);
    const p03Hit = answerVersionImpact(p03Items, { product: "log4j", version: "2.14.1", cve_id: "CVE-2021-44228" });
    check(p03Hit.status === "affected" && p03Hit.matched_ranges.includes("<=2.14.1"),
      "log4j 2.14.1 → affected 且命中区间 <=2.14.1（确定性规则）");
    const p03Unknown = answerVersionImpact(p03Items, { product: "log4j", version: "2.16.0" });
    check(p03Unknown.status === "unknown" && /不能排除受影响/.test(p03Unknown.reason),
      "规则含不可解析项时不过度结论：2.16.0 → unknown 且说明原因（禁硬判 not_affected）");
    const p03Absent = answerVersionImpact(p03Items, { product: "nginx", version: "1.0.0" });
    check(p03Absent.status === "unknown" && p03Absent.candidates === 0,
      "无该产品情报 → unknown（无法判定不等于安全）");
    // ② 进答案：问题带产品+版本槽位时，正文/推理链展示判定与依据
    const p03Turn: QueryTurn = { session_id: "sess_smoke_p03", turn_id: "turn_p03", text: "Log4Shell 2.14.1 是否受 CVE-2021-44228 影响？" };
    const p03Plan = classifyIntent(p03Turn);
    check(p03Plan.slots.products.length > 0 && p03Plan.slots.versions.length > 0,
      "Q1 抽出产品与版本槽位（" + JSON.stringify(p03Plan.slots.products) + " " + JSON.stringify(p03Plan.slots.versions) + "）");
    const p03Evidence = await engine.search({ query_id: "q_smoke_p03", query_text: p03Plan.rewrite_text, top_k: 5, trace_id: "tr_smoke_p03", schema_version: "1.0" });
    const p03Answer = await synthesizeAnswer(p03Turn.text, p03Plan, p03Evidence, {
      session_id: p03Turn.session_id, turn_id: p03Turn.turn_id, bus,
      version_impact: answerVersionImpact(p03Items, { product: p03Plan.slots.products[0]!, version: p03Plan.slots.versions[0]!, cve_id: p03Plan.slots.cve_ids[0] }),
    });
    check(p03Answer.text_md.includes("## 版本影响判定（确定性规则）") && p03Answer.text_md.includes("**受影响**"),
      "判定段与结论进答案正文");
    check(p03Answer.reasoning_chain.some((s) => s.includes("P-03 版本影响判定") && s.includes("非相似度/模型生成")),
      "推理链记录判定来自确定性规则");
  }

  // ---------- 13) A-01 编排挂起/恢复（threadId 持久化 + invoke/resume） ----------
  console.log("\n[13] A-01 编排挂起/恢复（threadId 持久化 + invoke/resume）");
  {
    const threadStore = new Store();
    const seen: string[] = [];
    const a01Spec: MachineSpec = {
      nodes: [
        { id: "monitor", role: "monitor", writes: ["log"], run: (state) => { seen.push("monitor"); state.log = "monitor-done"; } },
        { id: "enricher", role: "enricher", deps: ["monitor"], writes: ["log"], run: (state) => { seen.push("enricher"); state.enriched = state["__resume_value"] !== undefined; } },
        { id: "qa", role: "qa", deps: ["enricher"], run: (state) => { seen.push("qa"); state.answered = true; } },
      ],
      reducers: {},
    };
    const a01Config = { backend: "native", interrupts: { enabled: true, node_id: "enricher" } } as const;
    // ① invoke：执行到 enricher 挂起，检查点落库（suspended + 状态快照）
    const a01First = await runMachine(a01Spec, { store: threadStore, config: a01Config });
    check(a01First.interrupted && a01First.interrupted_at === "enricher",
      "invoke 到挂起点停下（interrupted_at=enricher）");
    check(JSON.stringify(a01First.executed) === JSON.stringify(["monitor"]), "挂起点前的节点已执行");
    const a01Cp = await threadStore.loadThreadCheckpoint(a01First.thread_id);
    check(a01Cp?.status === "suspended" && a01Cp.state.log === "monitor-done",
      "检查点落库：suspended + 挂起点状态快照（threadId 持久化）");
    // ② resume：跳过已执行、恢复值到达挂起节点、续跑完成、检查点转 completed
    const a01Resumed = await resumeMachine(a01First.thread_id, a01Spec, { store: threadStore, config: a01Config, resumeValue: { approved: true } });
    check(a01Resumed.ok && !a01Resumed.interrupted, "resume 后跑完剩余节点");
    check(JSON.stringify(seen) === JSON.stringify(["monitor", "enricher", "qa"]),
      "已执行节点不重跑（monitor 只出现一次）");
    check((await threadStore.loadThreadCheckpoint(a01First.thread_id))?.status === "completed",
      "完成后检查点转 completed");
    // ③ fail-closed：completed 线程禁止重复 invoke / resume
    let a01Rejected = 0;
    try { await runMachine(a01Spec, { store: threadStore, threadId: a01First.thread_id, config: a01Config }); } catch { a01Rejected += 1; }
    try { await resumeMachine(a01First.thread_id, a01Spec, { store: threadStore, config: a01Config, resumeValue: 1 }); } catch { a01Rejected += 1; }
    check(a01Rejected === 2, "completed 线程重复 invoke/resume 均显式抛错（fail-closed）");
    threadStore.close();
  }

  // ---------- 14) A-02 人工工单队列（转人工后有人接） ----------
  console.log("\n[14] A-02 人工工单队列（转人工后有人接）");
  {
    const ticketStore = new Store();
    const ticketBus = new EventBus({ store: ticketStore });
    const hqReq: DecisionRequest = {
      decision_id: "dec_smoke_ticket",
      kind: "q1_route",
      state: { question: "冒烟人工队列", private_marker: "do-not-store" },
      questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
      trace_id: "tr_smoke_ticket",
      schema_version: "1.1",
    };
    // ① 全链未决 → 入队（幂等；工单不落私有 state）
    const hqPending = await runDecisionLadder(hqReq, { bus: ticketBus, ticketStore: ticketStore });
    check(hqPending.reply.decided_by === "human" && hqPending.ticket_id === "ticket_dec_smoke_ticket",
      "全链未决：abstain + decided_by=human + 工单入队");
    const hqTicket = await ticketStore.getHumanTicket(hqPending.ticket_id!);
    check(hqTicket?.status === "pending" && !JSON.stringify(hqTicket).includes("do-not-store"),
      "工单 pending 且不落私有 state（只存 questions 与轨迹 id）");
    await runDecisionLadder(hqReq, { bus: ticketBus, ticketStore: ticketStore });
    check((await ticketStore.listHumanTickets()).length === 1, "同一 decision_id 重放不产生重复工单（幂等）");
    // ② 接单（重复接单被拒）
    const hqClaimed = await claimHumanTicket(ticketStore, hqPending.ticket_id!, "reviewer-smoke");
    check(hqClaimed.status === "claimed" && hqClaimed.claimed_by === "reviewer-smoke", "接单成功（pending → claimed）");
    let hqDoubleClaim = false;
    try { await claimHumanTicket(ticketStore, hqPending.ticket_id!, "reviewer-other"); } catch { hqDoubleClaim = true; }
    check(hqDoubleClaim, "重复接单显式抛错（不静默改状态）");
    // ③ 人工决单：契约校验 + decision.replies 回流 + 销单
    const hqResolved = await resolveHumanTicket({
      store: ticketStore, bus: ticketBus, ticket_id: hqPending.ticket_id!, resolver_id: "reviewer-smoke",
      decision: { choice: "remediation" }, rationale: "冒烟人工复核：按修复路径处置",
    });
    check(hqResolved.reply.decided_by === "human" && hqResolved.reply.decision.choice === "remediation",
      "人工决策以 decided_by=human 回流（契约通道）");
    check(hqResolved.ticket.status === "resolved" && hqResolved.ticket.reply_event_id !== undefined,
      "工单销单并关联 reply event_id（可回放）");
    const hqReplies = await ticketStore.read<DecisionReply>("decision.replies");
    check(hqReplies.some((e) => e.payload.decided_by === "human" && e.payload.decision.choice === "remediation"),
      "decision.replies 可 replay 到人工决策");
    const hqLineage = await ticketStore.readLineage("tr_smoke_ticket");
    check(hqLineage.some((r) => r.stage === "human.ticket_resolve" && r.status === "success")
      && !JSON.stringify(hqLineage).includes("do-not-store"),
      "人工决单落 lineage 且不复制私有 state");
    // ④ 重复决单被拒
    let hqDoubleResolve = false;
    try {
      await resolveHumanTicket({ store: ticketStore, bus: ticketBus, ticket_id: hqPending.ticket_id!, resolver_id: "r2", decision: { abstain: true } });
    } catch { hqDoubleResolve = true; }
    check(hqDoubleResolve, "重复决单显式抛错（fail-closed）");
    ticketStore.close();
  }

  // ---------- 15) A-06 常驻自愈（服务进程订阅 + 周期 drain/healthcheck） ----------
  console.log("\n[15] A-06 常驻自愈（SelfHealDaemon：订阅 + 周期拍）");
  {
    const daemonStore = new Store();
    let daemonBroken = true;
    let daemon: SelfHealDaemon | undefined;
    const daemonBus = new EventBus({
      store: daemonStore,
      maxRetries: 1,
      onDeadLetter: (eventId, reason) => daemon?.agent.noteDeadLetter(eventId, reason),
    });
    daemonBus.subscribe("decision.replies", async () => {
      if (daemonBroken) throw new Error("smoke: daemon consumer broken");
    });
    const tickReports: unknown[] = [];
    let daemonNow = 1_800_000_000_000; // 注入时钟：冒烟里可推进退避窗（确定性）
    daemon = new SelfHealDaemon({
      bus: daemonBus, store: daemonStore,
      now: () => daemonNow,
      backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 8 },
      onTick: (report) => { tickReports.push(report); },
    });
    // ① 常驻订阅：fallback.events 登记（兜底透明率 100%）
    daemon.start();
    await degrade({
      layer: "L3",
      trigger: "smoke selfheal daemon spot-check",
      degradedOf: "smoke:selfheal-daemon",
      traceId: "tr_smoke_daemon",
      label: "冒烟常驻自愈抽检（显式降级）",
      emit: async (event) => { await daemonBus.publish("fallback.events", event, { trace_id: event.trace_id }); },
    });
    check(daemon.agent.registeredFallbackEvents.length === 1, "常驻进程订阅并登记降级事件（兜底透明率 100%）");
    // ② 造 3 条死信后首拍：重投失败排退避（消费者仍坏）
    for (let i = 0; i < 3; i += 1) {
      const reply: DecisionReply = {
        decision_id: "dec_smoke_daemon_" + i,
        kind: "q1_route",
        decision: { choice: "impact_range" },
        calibrated_prob: 0.9,
        decided_by: "rule_fallback",
        schema_version: "1.0",
      };
      await daemonBus.publish("decision.replies", reply, { trace_id: "tr_smoke_daemon_dl" });
    }
    const daemonTick1 = await daemon.tick();
    check(daemonTick1.drain.retried === 3 && daemonTick1.drain.recovered === 0,
      "首拍重投 3 条全部失败（消费者仍坏，retried=" + daemonTick1.drain.retried + "）");
    check(daemonTick1.health.dead_letters === 3 && daemonTick1.health.retry_scheduled === 3,
      "healthcheck 聚合：3 条死信 + 3 条退避排队（显式可见）");
    check(tickReports.length === 1, "每拍报告显式交出（禁静默自愈）");
    // ③ 修复消费者 + 推进时钟越过退避窗，第二拍全部恢复、死信清零
    daemonBroken = false;
    daemonNow += 1500;
    const daemonTick2 = await daemon.tick();
    check(daemonTick2.drain.recovered === 3, "修复后到拍重投 3 条全部恢复（recovered=" + daemonTick2.drain.recovered + "）");
    check(daemonTick2.health.dead_letters === 0 && daemonTick2.health.retry_scheduled === 0,
      "恢复后死信与退避队列清零");
    check(daemon.agent.deadLetterNotifications.length >= 3, "总线死信通知到达自愈 Agent（" + daemon.agent.deadLetterNotifications.length + " 条）");
    // ④ stop 退净订阅
    daemon.stop();
    await daemonBus.publish("fallback.events", {
      event_id: "fb_after_stop", layer: "L3", trigger: "after stop", action_taken: "none",
      degraded_of: "smoke:after-stop", user_visible: true,
      degraded_state: { label: "停止后", since: nowIso(), detail_ref: "tr:x" }, trace_id: "tr_smoke_daemon_after",
    }, { trace_id: "tr_smoke_daemon_after" });
    check(daemon.agent.registeredFallbackEvents.length === 1, "stop 后不再登记（订阅已退净）");
    daemonStore.close();
  }

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
