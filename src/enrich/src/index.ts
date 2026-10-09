/**
 * F 线编排（index）：runEnrichment = F1 论文 + F4 分值/EPSS -> F6 收口，
 * 每个 Result 的 artifacts 均带 source 字段（papers[].source / score_assessment.source_of_score），
 * 并按契约发布到总线主题 enrich.papers / enrich.items。
 *
 * 降级纪律（红线：禁止静默兜底）：
 * - 外网调用（arXiv / EPSS）离线或失败 -> fixture 回放 + degrade() 上总线 fallback.events
 * - EnrichmentResult.json 契约 additionalProperties:false，信封 payload 一律剥离 conflicts 等审计字段
 * - 无可用评分来源 -> cvss 维度记失败（assessScore 返回 null），不造假分
 */
import { enrichmentInputHash, enrichmentRetryDue, enrichmentRetryAfter, degrade, nextId, nowIso, SCHEMA_VERSION, sha256Json } from "@safetrace/shared";
import type { EventBus, FallbackEvent, IntelItem, EnrichmentResult, LineageArtifactRef, PaperLink, ScoreAssessment, EnrichmentStateStore, EnrichmentDimension, EnrichmentStatus, EnrichmentDimensionState } from "@safetrace/shared";
import {
  assessScore,
  lookupEpss,
  loadScoreSourcesFromRawRefs,
  scoreSourceDependencyHash,
  type HttpFetcher,
  type ScoreSourceInput,
  type EpssLookup,
} from "./f4-cvss.js";
import { searchPapers, anchoredPapers, buildPaperQuery } from "./f1-papers.js";
import type { PaperReviewOutcome, PaperReviewPort } from "./stepfun-paper-review.js";
import {
  computeEnrichmentScore,
  type EnrichmentOutcome,
  type ScoreConflict,
  summarizeEnrichment,
} from "./f6-verify.js";

export * from "./f4-cvss.js";
export * from "./f2-assets.js";
export * from "./f1-papers.js";
export * from "./stepfun-paper-review.js";
export * from "./jev-paper-review.js";
export * from "./extension-receipts.js";
export * from "./poc-candidates.js";
export * from "./jev-decision-client.js";
export * from "./triage.js";
export * from "./f6-verify.js";

import type { ExtensionDimension, ExtensionRunSummary } from "./extension-receipts.js";

export interface EnrichContext {
  stateStore?: EnrichmentStateStore;
  now?: Date;
  offline?: boolean;
  kevSet?: Iterable<string>;
  fetchImpl?: HttpFetcher;
  bus?: EventBus;
  /** 分值源（ingest/Y 线注入，可含多源）。缺失时从 raw_refs 指向的本地 payload 复原；
   *  两者皆无 -> cvss 维度记失败（在线）或走 raw_refs fixture（离线）。 */
  scoreSources?: ScoreSourceInput[];
  traceId?: string;
  /** Optional parent links handed off by the ingest run for each IntelItem. */
  lineage_parent_by_intel_id?: Record<string, string>;
  causation_by_intel_id?: Record<string, string>;
  /** 降级观察者（FallbackEvent，与 fallback.events 同口径；前端横幅据此渲染）。 */
  onDegrade?: (event: FallbackEvent) => void | Promise<void>;
  /** 多源分差观察者（conflicts 审计信息，不在 EnrichmentResult 契约内）。 */
  onConflict?: (conflict: ScoreConflict, intelId: string) => void | Promise<void>;
  /** Optional F1 paper review sidecar (StepPlan or local Open-Jev); it must never reorder or modify published scores by itself. */
  paperReviewer?: PaperReviewPort;
  /** 评审提供方标识（落 lineage stage/execution）；缺省 stepplan 保持历史口径。 */
  paperReviewerProvider?: string;
  onPaperReview?: (intelId: string, outcome: PaperReviewOutcome) => void | Promise<void>;
  /**
   * 本轮只跑这些维度（运维用：例如只补 cvss/epss 时不发起 arXiv 请求）。
   * 未列出维度既不请求也不改写状态；缺省为全部三维度。
   */
  dimensions?: readonly EnrichmentDimension[];
  /** Explicit typed sidecars; never injected into the frozen enrich.items payload. */
  extensionDimensions?: readonly ExtensionDimension[];
  extensionRunner?: (item: IntelItem, dimension: ExtensionDimension) => Promise<ExtensionRunSummary>;
  onExtension?: (intelId: string, summary: ExtensionRunSummary) => void | Promise<void>;
}

/** 富化一批情报。单个条目内部失败直接抛错（显式失败，不静默跳过）。 */
export async function runEnrichment(items: IntelItem[], ctx: EnrichContext = {}): Promise<EnrichmentResult[]> {
  const extensions = ctx.extensionDimensions ?? [];
  if (extensions.some(d=>!["remediation","asset","poc"].includes(d)) || new Set(extensions).size!==extensions.length || (extensions.length && !ctx.extensionRunner)) throw new Error("Unsupported/missing explicit extension runner");
  const results: EnrichmentResult[] = [];
  for (const item of items) {
    // extensions-only runs do not fetch papers/scores or rewrite historical enrich.items receipts.
    const outcome = ctx.dimensions?.length === 0 ? summarizeEnrichment(item,{}) : await enrichOne(item, ctx);
    for (const dimension of extensions) {
      const trace = ctx.traceId ?? nextId("tr");
      let summary: ExtensionRunSummary;
      try {
        summary = await ctx.extensionRunner!(item,dimension);
        if(summary.dimension!==dimension || !summary.receipt_id || !["live","empty"].includes(summary.status) || !Number.isSafeInteger(summary.artifacts) || summary.artifacts<0 || (summary.status === "live") !== (summary.artifacts > 0)) throw new Error("Invalid committed extension summary");
      } catch(error) {
        await ctx.bus?.recordLineage({trace_id:trace,causation_id:ctx.causation_by_intel_id?.[item.intel_id]??null,stage:dimension==="asset"?"enrich.f2_assets":dimension==="poc"?"enrich.f3_poc":"enrich.f5_remediation",operation_version:dimension==="asset"?"asset-extension.v1":dimension==="poc"?"poc-extension.v1":"remediation-extension.v1",status:"failed",input_refs:[{kind:"IntelItem",id:item.intel_id,sha256:sha256Json(item)}],error:"extension failed; no success receipt reported"});
        throw error;
      }
      await ctx.bus?.recordLineage({trace_id:trace,causation_id:ctx.causation_by_intel_id?.[item.intel_id]??null,stage:dimension==="asset"?"enrich.f2_assets":dimension==="poc"?"enrich.f3_poc":"enrich.f5_remediation",operation_version:dimension==="asset"?"asset-extension.v1":dimension==="poc"?"poc-extension.v1":"remediation-extension.v1",status:summary.status==="live"?"success":"review",input_refs:[{kind:"IntelItem",id:item.intel_id,sha256:sha256Json(item)}],output_refs:[{kind:"ExtensionReceipt",id:summary.receipt_id,sha256:sha256Json(summary)}],decision:{reason:dimension==="asset"?"Local asset rule assessment; vendor identity unverified; unknown is not safety; frozen result unchanged":dimension==="poc"?"Advisory-tagged PoC references with local model advisory; no content fetched, nothing executed, reachability/exploitability unverified; frozen result unchanged":"Independent source-backed guidance receipt; not a verified repair; frozen result unchanged"}});
      await ctx.onExtension?.(item.intel_id,summary);
    }
    results.push(outcome);
  }
  return results;
}

function shouldAskPaperReviewer(papers: PaperLink[]): boolean {
  if (papers.length < 2) return false;
  const [first, second] = papers;
  return first!.confidence < 0.8 || first!.relevance_score - second!.relevance_score < 0.12;
}

async function enrichOne(item: IntelItem, ctx: EnrichContext): Promise<EnrichmentOutcome> {
  const traceId = ctx.traceId ?? nextId("tr");
  const inputHash = enrichmentInputHash(item);
  const now = ctx.now ?? new Date();
  const prior = (dimension: EnrichmentDimension) => ctx.stateStore?.get(item.intel_id, dimension);
  const inScope = (dimension: EnrichmentDimension) => ctx.dimensions === undefined || ctx.dimensions.includes(dimension);
  const due = (dimension: EnrichmentDimension) => inScope(dimension) && (!ctx.stateStore || enrichmentRetryDue(prior(dimension), inputHash, now));
  const causation = ctx.causation_by_intel_id?.[item.intel_id] ?? null;
  let needsReceipt = Boolean(ctx.bus && ctx.stateStore && (["paper", "cvss", "epss"] as const).some(dimension => { if (!inScope(dimension)) return false; const s = prior(dimension); return s && (!s.enrich_event_id || (causation && s.intel_event_id !== causation)); }));
  if (ctx.bus && ctx.stateStore && (["paper", "cvss", "epss"] as const).some(d => prior(d))) {
    let latest: Awaited<ReturnType<EventBus["readEvents"]>>[number] | undefined;
    for (let offset = 0; ; offset += 500) { const page = await ctx.bus.readEvents<EnrichmentResult>("enrich.items", offset, 500); for (const event of page) if (event.payload.intel_id === item.intel_id) latest = event; if (page.length < 500) break; }
    if (!latest || (["paper", "cvss", "epss"] as const).some(d => inScope(d) && prior(d) && prior(d)!.enrich_event_id !== latest!.event_id)) needsReceipt = true;
  }
  const runPaper = due("paper");
  const scoreDependency = await scoreSourceDependencyHash(item, { sources: ctx.scoreSources, kevSet: ctx.kevSet });
  const runCvss = due("cvss") || prior("cvss")?.dependency_hash !== scoreDependency;
  const runEpss = due("epss");
  if (!runPaper && !runCvss && !runEpss && !needsReceipt) return summarizeEnrichment(item, { papers: (prior("paper")?.artifact ?? []) as PaperLink[], scoreAssessment: (prior("cvss")?.artifact ?? null) as ScoreAssessment | null });
  const states: Array<{ dimension: EnrichmentDimension; status: EnrichmentStatus; reason: string; artifact: unknown; judgement?: string }> = [];
  let paperProvenance: EnrichmentDimensionState["provenance"];
  let paperMetadataUnknown = false;
  let epssReceipt: EpssLookup | undefined;
  const save = (dimension: EnrichmentDimension, status: EnrichmentStatus, reason: string, artifact: unknown, eventId: string | null) => {
    const attempts = (prior(dimension)?.attempts ?? 0) + 1;
    ctx.stateStore?.put({ intel_id: item.intel_id, dimension, status, reason, artifact, input_hash: inputHash,
      result_hash: sha256Json(artifact), enrich_event_id: eventId, intel_event_id: causation,
      ...(dimension === "paper" && paperProvenance ? { provenance: paperProvenance } : {}),
      ...(dimension === "epss" && epssReceipt?.receipt ? { source_receipt: epssReceipt.receipt } : {}),
      ...(dimension === "cvss" ? { dependency_hash: scoreDependency } : {}), retry_after: enrichmentRetryAfter(status, attempts, now), attempts, updated_at: now.toISOString() });
  };
  const itemRef: LineageArtifactRef = { kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) };
  const inputParent = ctx.lineage_parent_by_intel_id?.[item.intel_id];
  const fallbackRefs: LineageArtifactRef[] = [];
  const emit = makeEmitter(ctx, fallbackRefs, itemRef, inputParent, causation);

  // F1：论文关联
  const f1Started = nowIso();
  const f1FallbackStart = fallbackRefs.length;
  let papersRes: Awaited<ReturnType<typeof searchPapers>>;
  try {
    const paperQuery = runPaper ? buildPaperQuery(item) : "";
    const paperContext = [item.title, item.entities.product ?? "", item.cve_ids.join(" ")].filter(Boolean).join(" ");
    papersRes = runPaper ? await searchPapers(paperQuery, { offline: ctx.offline, fetchImpl: ctx.fetchImpl, traceId, emit, relevanceContext: paperContext }) : { papers: (prior("paper")?.artifact ?? []) as PaperLink[], ...(prior("paper")?.status === "degraded" ? { degraded_to: "fixture" } : {}) };
    if (runPaper) {
      if (!papersRes.degraded_to) {
        const related = anchoredPapers(item, papersRes.papers, papersRes.paper_records);
        papersRes.papers = related.filter(paper => papersRes.paper_records?.[paper.paper_id]?.title === paper.title);
        paperMetadataUnknown = related.length > papersRes.papers.length;
        if (papersRes.source_evidence && papersRes.paper_records) paperProvenance = { query_url: papersRes.source_evidence.url, sha256: papersRes.source_evidence.sha256, text: papersRes.source_evidence.text, paper_records: papersRes.paper_records };
      }
      states.push({ dimension: "paper", status: papersRes.degraded_to ? "degraded" : papersRes.papers.length ? "live" : paperMetadataUnknown ? "unknown" : "empty", reason: papersRes.degraded_to ? "fixture paper replay; not real success" : papersRes.papers.length ? "entity/topic candidates with original arXiv metadata; heuristic relevance, not accuracy" : paperMetadataUnknown ? "candidate publication metadata/identity unverified" : "no related candidates; empty backoff", artifact: papersRes.papers, judgement: papersRes.degraded_to ? undefined : "判断：召回 " + (papersRes.paper_records ? Object.keys(papersRes.paper_records).length : 0) + " 篇，判相关 " + papersRes.papers.length + " 篇，判不相关 " + Math.max(0, (papersRes.paper_records ? Object.keys(papersRes.paper_records).length : 0) - papersRes.papers.length) + " 篇" });
    }
  } catch {
    await ctx.bus?.recordLineage({
      trace_id: traceId, parent_lineage_ids: inputParent ? [inputParent] : [], causation_id: causation,
      stage: "enrich.f1", operation_version: "f1-papers.v1", status: "failed", started_at: f1Started,
      input_refs: [itemRef], error: "paper enrichment failed",
    });
    save("paper", "failed", "paper enrichment failed", null, null);
    throw new Error("F1 富化失败；lineage 已记录 trace_id=" + traceId + " intel_id=" + item.intel_id);
  }
  const paperPayload = papersPayload(item.intel_id, papersRes.papers);
  const papersEnv = runPaper ? await ctx.bus?.publish("enrich.papers", paperPayload, { trace_id: traceId, causation_id: causation }) : undefined;
  const paperRefs: LineageArtifactRef[] = papersRes.papers.map((paper) => ({ kind: "PaperLink", id: paper.paper_id, sha256: sha256Json(paper) }));
  if (papersEnv) paperRefs.push({ kind: "EventEnvelope", id: papersEnv.event_id, sha256: sha256Json(paperPayload) });
  const f1FallbackRefs = fallbackRefs.slice(f1FallbackStart);
  const f1Lineage = await ctx.bus?.recordLineage({
    trace_id: traceId, parent_lineage_ids: inputParent ? [inputParent] : [],
    causation_id: papersEnv?.event_id ?? causation,
    stage: "enrich.f1", operation_version: "f1-papers.v1",
    status: papersRes.degraded_to ? "degraded" : "success", started_at: f1Started,
    input_refs: [itemRef, ...item.raw_refs.map((id) => ({ kind: "RawDocRef", id }))],
    output_refs: [...paperRefs, ...f1FallbackRefs],
    source: { source_id: item.source_ids.join(",") },
    ...(papersRes.degraded_to ? { decision: { fallback_to: papersRes.degraded_to, reason: "paper search returned fallback fixture" } } : {}),
  });

  // Optional F1 paper review advice (StepPlan or local Open-Jev): sidecar only; never changes PaperLink scores, order, or published EnrichmentResult.
  // 历史 stage 名为 enrich.f1_stepfun_advisory；默认值保持 stepfun 以兼容既有 lineage 查询，
  // 本地 Jev 评审由 enrich-pending 传 paperReviewerProvider="openjev"（stage: enrich.f1_openjev_advisory）。
  const reviewerProvider = ctx.paperReviewerProvider ?? "stepfun";
  if (runPaper && ctx.paperReviewer && ctx.bus && !papersRes.degraded_to && shouldAskPaperReviewer(papersRes.papers)) {
    const candidates = papersRes.papers.map((paper) => ({
      paper_id: paper.paper_id,
      title: paper.title,
      ...(paper.year !== undefined ? { year: paper.year } : {}),
      rule_relevance_score: paper.relevance_score,
      evidence_terms: paper.evidence_terms ?? [],
    }));
    const projection = { query: item.title, candidates };
    const projectionHash = sha256Json(projection);
    // 摘要只来自本次 arXiv 原始回执（paper_records），且仅传给声明消费它的评审端；
    // StepFun 云端评审不读摘要（契约原因），本地 Jev 评审读（语义判断需要）。
    const paperSummaries = Object.fromEntries(Object.entries(papersRes.paper_records ?? {})
      .filter(([id, record]) => papersRes.papers.some(paper => paper.paper_id === id) && record.title === papersRes.papers.find(paper => paper.paper_id === id)!.title)
      .map(([id, record]) => [id, record.summary.slice(0, 1000)]));
    const reviewStarted = nowIso();
    let reviewOutcome: PaperReviewOutcome;
    let reviewFailed = false;
    try {
      const reviewerPapers = papersRes.papers.map((paper) => ({ ...paper, ...(paper.evidence_terms ? { evidence_terms: [...paper.evidence_terms] } : {}) }));
      reviewOutcome = await ctx.paperReviewer({ trace_id: traceId, intel_id: item.intel_id, query: item.title, papers: reviewerPapers, ...(Object.keys(paperSummaries).length ? { paper_summaries: paperSummaries } : {}) });
    } catch {
      reviewFailed = true;
      await ctx.bus.recordLineage({
        trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
        causation_id: papersEnv?.event_id ?? causation, stage: "enrich.f1_" + reviewerProvider + "_advisory", operation_version: reviewerProvider + ".f1-advisory.v1", status: "degraded", started_at: reviewStarted,
        input_refs: [{ kind: "F1PaperReviewProjection", id: item.intel_id, sha256: projectionHash }],
        decision: { fallback_to: "rule-ranked-papers", reason: reviewerProvider + " review failed; deterministic F1/F4/F6 outputs remain unchanged" },
        error: "paper review request failed; source text omitted",
      });
      await degrade({
        layer: "L3", trigger: reviewerProvider + " F1 advisory failed; deterministic paper results retained", degradedOf: "rule-ranked-papers", traceId,
        label: "论文评审建议不可用；F1 规则结果未改变", recoveryHint: reviewerProvider === "stepfun" ? "检查 planner provider/key；不会改写论文来源、相关分或 F6 总分。" : "检查本地 Jev 服务（JEV_BASE_URL）与 JEV_MODEL_ID；不会改写论文来源、相关分或 F6 总分。",
        emit: async (event) => emit(event),
      });
      reviewOutcome = { status: "abstained", reason: "review request failed" };
    }
    if (!reviewFailed) {
      const candidateIds = new Set(papersRes.papers.map((paper) => paper.paper_id));
      if (reviewOutcome.status === "suggested" && (reviewOutcome.paper_ids.length < 1 || reviewOutcome.paper_ids.length > candidates.length || new Set(reviewOutcome.paper_ids).size !== reviewOutcome.paper_ids.length || reviewOutcome.paper_ids.some((id) => !candidateIds.has(id)) || !Number.isFinite(reviewOutcome.confidence) || reviewOutcome.confidence < 0.8 || reviewOutcome.confidence > 1)) {
        reviewOutcome = { status: "abstained", reason: "paper suggestion failed candidate/threshold validation", model_id: reviewOutcome.model_id, provider: reviewOutcome.provider };
      }
      const suggested = reviewOutcome.status === "suggested" ? reviewOutcome : undefined;
      const suggestionRefs = suggested
        ? suggested.paper_ids.map((paperId) => ({ kind: "PaperReviewSuggestion", id: paperId, sha256: sha256Json({ paper_id: paperId, confidence: suggested.confidence }) }))
        : [];
      await ctx.bus.recordLineage({
        trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
        causation_id: papersEnv?.event_id ?? causation, stage: "enrich.f1_" + reviewerProvider + "_advisory", operation_version: reviewerProvider + ".f1-advisory.v1", status: "review", started_at: reviewStarted,
        input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: inputHash }, { kind: "F1PaperReviewProjection", id: item.intel_id, sha256: projectionHash }],
        output_refs: suggestionRefs,
        execution: reviewOutcome.model_id ? { provider: reviewOutcome.provider ?? "stepplan", model_id: reviewOutcome.model_id, model_version: reviewOutcome.provider === "openjev" ? "pinned-local" : "unversioned-api" } : { component_version: reviewerProvider + ".f1-advisory.v1" },
        decision: { reason: reviewOutcome.status === "suggested" ? reviewerProvider + " ranking is advisory only; F1 scores/order and published EnrichmentResult remain rule-derived" : reviewerProvider + " F1 advisory abstained: " + reviewOutcome.reason, review_required: true },
      });
      try { await ctx.onPaperReview?.(item.intel_id, reviewOutcome); }
      catch {
        await degrade({
          layer: "L3", trigger: "F1 advisory observer failed; model suggestion was not applied", degradedOf: "rule-ranked-papers", traceId,
          label: "F1 建议展示回调失败；规则结果保持不变", recoveryHint: "检查本地诊断输出；F1/F4/F6 契约未受影响。",
          emit: async (event) => emit(event),
        });
      }
    }
  }

  // F4：分值仲裁 + EPSS 增强
  const f4Started = nowIso();
  const f4FallbackStart = fallbackRefs.length;
  let sources: ScoreSourceInput[];
  let score: Awaited<ReturnType<typeof assessScore>>;
  try {
    sources = runCvss ? ctx.scoreSources ?? (await loadScoreSourcesFromRawRefs(item)) : [];
    const epssEvents: FallbackEvent[] = [];
    const scoreEmit = async (event: FallbackEvent) => { epssEvents.push(event); await emit(event); };
    score = runCvss ? await assessScore(item, { sources, kevSet: ctx.kevSet, offline: ctx.offline, fetchImpl: ctx.fetchImpl, traceId, emit: scoreEmit, skipEpss: !runEpss, onEpssLookup: value => { epssReceipt = value; } }) : (prior("cvss")?.artifact ?? null) as ScoreAssessment | null;
    if (runCvss && !runEpss && score && prior("epss")) {
      const retained = prior("epss")!.artifact as { epss_score: number | null; epss_percentile: number | null } | null;
      delete score.epss_score; delete score.epss_percentile;
      if (retained?.epss_score != null) score.epss_score = retained.epss_score;
      if (retained?.epss_percentile != null) score.epss_percentile = retained.epss_percentile;
    }
    // FIRST scoring is independent of CVSS availability; unproved injected EPS is not a receipt.
    if (runEpss && !epssReceipt && item.cve_ids.length) {
      epssReceipt = await lookupEpss(item.cve_ids[0]!, { offline: ctx.offline, fetchImpl: ctx.fetchImpl, traceId, emit: scoreEmit });
    }
    if (runEpss && epssReceipt && score) {
      score = { ...score };
      delete score.epss_score; delete score.epss_percentile;
      if (epssReceipt.epss_score !== null) score.epss_score = epssReceipt.epss_score;
      if (epssReceipt.epss_percentile !== null) score.epss_percentile = epssReceipt.epss_percentile;
    }
    if (runCvss) states.push({ dimension: "cvss", status: score ? (!ctx.scoreSources && item.raw_refs.some(ref => /(?:^|[\\/])fixtures[\\/]/.test(ref)) ? "degraded" : "live") : "empty", reason: score ? (!ctx.scoreSources && item.raw_refs.some(ref => /(?:^|[\\/])fixtures[\\/]/.test(ref)) ? "fixture CVSS source; not real success" : "source-backed CVSS; EPSS tracked independently") : "no usable CVSS source; empty backoff", artifact: score });
    if (runEpss) {
      const date = epssReceipt?.receipt?.as_of_date;
      const age = date ? now.getTime() - Date.parse(date + "T00:00:00Z") : NaN;
      const genuine = !ctx.offline && !epssReceipt?.degraded_to && !!epssReceipt?.receipt && Number.isFinite(age) && age >= -5 * 60_000 && age <= 2 * 24 * 3600_000;
      const status: EnrichmentStatus = ctx.offline || epssEvents.length ? "degraded" : genuine ? "live" : (epssReceipt?.epss_score != null || score?.epss_score !== undefined) ? "unknown" : "empty";
      states.push({ dimension: "epss", status, reason: status === "live" ? "FIRST response and recent as-of date verified" : status === "degraded" ? "offline/fixture EPSS; CVSS tracked independently" : status === "unknown" ? "EPSS supplied without verified recent source receipt; not real success" : "no EPSS data; empty backoff", artifact: epssReceipt ? { epss_score: epssReceipt.epss_score, epss_percentile: epssReceipt.epss_percentile } : score ? { epss_score: score.epss_score ?? null, epss_percentile: score.epss_percentile ?? null } : null });
    }
  } catch {
    await ctx.bus?.recordLineage({
      trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
      causation_id: papersEnv?.event_id ?? causation,
      stage: "enrich.f4", operation_version: "f4-cvss.v1", status: "failed", started_at: f4Started,
      input_refs: [itemRef], error: "score assessment failed",
    });
    for (const state of states) save(state.dimension, state.status, state.reason, state.artifact, null);
    save(runCvss ? "cvss" : "epss", "failed", "score assessment failed", null, null);
    throw new Error("F4 富化失败；lineage 已记录 trace_id=" + traceId + " intel_id=" + item.intel_id);
  }
  const f4FallbackRefs = fallbackRefs.slice(f4FallbackStart);
  const f4Lineage = await ctx.bus?.recordLineage({
    trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
    causation_id: papersEnv?.event_id ?? causation,
    stage: "enrich.f4", operation_version: "f4-cvss.v1",
    status: f4FallbackRefs.length > 0 ? "degraded" : score ? "success" : "degraded", started_at: f4Started,
    input_refs: [itemRef, ...sources.map((source, index) => ({ kind: "ScoreSource", id: item.intel_id + ":" + index, sha256: sha256Json(source) }))],
    output_refs: [...(score ? [{ kind: "ScoreAssessment", id: item.intel_id, sha256: sha256Json(score) }] : []), ...f4FallbackRefs],
    source: { source_id: item.source_ids.join(",") },
    ...(!score ? { decision: { reason: "no usable score source" } } : f4FallbackRefs.length > 0 ? { decision: { fallback_to: "fixture", reason: "score enrichment emitted fallback" } } : {}),
  });

  // F6：收口（内存侧带 conflicts；总线侧发布契约纯净 payload）
  const f6Started = nowIso();
  let outcome: EnrichmentOutcome;
  let contractPayload: EnrichmentResult;
  let enrichEnv: Awaited<ReturnType<EventBus["publish"]>> | undefined;
  try {
    outcome = summarizeEnrichment(item, { papers: papersRes.papers, scoreAssessment: score, otherScores: sources });
    for (const conflict of outcome.conflicts) await ctx.onConflict?.(conflict, item.intel_id);
    contractPayload = toContractPayload(outcome);
    enrichEnv = await ctx.bus?.publish("enrich.items", contractPayload, {
      trace_id: traceId, causation_id: causation,
    });
  } catch {
    await ctx.bus?.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: [f1Lineage?.lineage_id, f4Lineage?.lineage_id].filter((id): id is string => Boolean(id)),
      causation_id: papersEnv?.event_id ?? causation,
      stage: "enrich.f6", operation_version: "f6-verify.v1", status: "failed", started_at: f6Started,
      input_refs: [itemRef, { kind: "PaperSet", id: item.intel_id, sha256: sha256Json(papersRes.papers) }, ...(score ? [{ kind: "ScoreAssessment", id: item.intel_id, sha256: sha256Json(score) }] : [])],
      error: "F6 consolidation or enrich.items publish failed",
    });
    for (const state of states) save(state.dimension, "failed", "enrichment publication failed; not committed as success", state.artifact, null);
    throw new Error("F6 富化收口失败；lineage 已记录 trace_id=" + traceId + " intel_id=" + item.intel_id);
  }
  await ctx.bus?.recordLineage({
    trace_id: traceId,
    parent_lineage_ids: [f1Lineage?.lineage_id, f4Lineage?.lineage_id].filter((id): id is string => Boolean(id)),
    causation_id: enrichEnv?.event_id ?? papersEnv?.event_id ?? causation,
    stage: "enrich.f6", operation_version: "f6-verify.v1", status: "success", started_at: f6Started,
    input_refs: [itemRef, { kind: "PaperSet", id: item.intel_id, sha256: sha256Json(papersRes.papers) }, ...(score ? [{ kind: "ScoreAssessment", id: item.intel_id, sha256: sha256Json(score) }] : [])],
    output_refs: [
      { kind: "EnrichmentResult", id: item.intel_id, sha256: sha256Json(contractPayload) },
      ...(enrichEnv ? [{ kind: "EventEnvelope", id: enrichEnv.event_id, sha256: sha256Json(contractPayload) }] : []),
    ],
    source: { source_id: item.source_ids.join(",") },
    ...(outcome.conflicts.length > 0 ? { decision: { reason: "observed " + outcome.conflicts.length + " score conflict(s)" } } : {}),
  });
  const commitStates = () => {
  for (const state of states) save(state.dimension, state.status, state.reason, state.artifact, enrichEnv?.event_id ?? null);
  // Retained CVSS is unchanged by an EPSS-only retry, but the combined artifact carries the updated auxiliary values.
  if (!runCvss && runEpss && prior("cvss") && score) ctx.stateStore?.put({ ...prior("cvss")!, artifact: score, result_hash: sha256Json(score), enrich_event_id: enrichEnv?.event_id ?? null, intel_event_id: causation });
  for (const dimension of ["paper", "cvss", "epss"] as const) {
    const retained = prior(dimension);
    if (!states.some(state => state.dimension === dimension) && retained) ctx.stateStore?.put({ ...retained, enrich_event_id: enrichEnv?.event_id ?? null, intel_event_id: causation });
  }
  };
  if (ctx.stateStore?.atomic) ctx.stateStore.atomic(commitStates); else commitStates();
  return outcome;
}

function makeEmitter(
  ctx: EnrichContext,
  refs: LineageArtifactRef[],
  inputRef: LineageArtifactRef,
  parentLineageId: string | undefined,
  causationId: string | null,
): (event: FallbackEvent) => Promise<void> {
  return async (event: FallbackEvent) => {
    if (ctx.bus) {
      const env = await ctx.bus.publish("fallback.events", event, { trace_id: event.trace_id, causation_id: causationId });
      const ref = { kind: "FallbackEvent", id: env.event_id, sha256: sha256Json(event) };
      refs.push(ref);
      await ctx.bus.recordLineage({
        trace_id: event.trace_id,
        parent_lineage_ids: parentLineageId ? [parentLineageId] : [],
        causation_id: env.event_id,
        stage: "enrich.fallback", operation_version: "fallback.events.v1", status: "degraded",
        input_refs: [inputRef], output_refs: [ref],
        decision: { fallback_to: event.degraded_of, reason: event.action_taken },
      });
    }
    await ctx.onDegrade?.(event);
  };
}

/** enrich.papers 信封 payload（EnrichmentResult 的 papers 维度形态，契约 required 字段齐全）。 */
function papersPayload(intelId: string, papers: EnrichmentResult["artifacts"]["papers"]): EnrichmentResult {
  const done = papers !== undefined && papers.length > 0;
  return {
    intel_id: intelId,
    dimensions_completed: done ? ["paper"] : [],
    dimensions_failed: done ? [] : ["paper"],
    artifacts: { ...(done && papers ? { papers } : {}) },
    enrichment_score: computeEnrichmentScore(1, done ? 1 : 0),
    completed_at: nowIso(),
    schema_version: SCHEMA_VERSION,
  };
}

/** 从 F6 outcome 得到总线用的契约纯净 payload（剥离 conflicts 审计字段）。 */
export function toContractPayload(outcome: EnrichmentOutcome): EnrichmentResult {
  const { conflicts, ...contractPayload } = outcome;
  void conflicts;
  return contractPayload;
}
