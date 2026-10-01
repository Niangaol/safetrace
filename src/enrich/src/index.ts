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
import { degrade, nextId, nowIso, SCHEMA_VERSION, sha256Json } from "@safetrace/shared";
import type { EventBus, FallbackEvent, IntelItem, EnrichmentResult, LineageArtifactRef, PaperLink } from "@safetrace/shared";
import {
  assessScore,
  loadScoreSourcesFromRawRefs,
  type HttpFetcher,
  type ScoreSourceInput,
} from "./f4-cvss.js";
import { searchPapers } from "./f1-papers.js";
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
export * from "./f6-verify.js";

export interface EnrichContext {
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
  /** Optional StepPlan F1 review sidecar; it must never reorder or modify published scores by itself. */
  paperReviewer?: PaperReviewPort;
  onPaperReview?: (intelId: string, outcome: PaperReviewOutcome) => void | Promise<void>;
}

/** 富化一批情报。单个条目内部失败直接抛错（显式失败，不静默跳过）。 */
export async function runEnrichment(items: IntelItem[], ctx: EnrichContext = {}): Promise<EnrichmentResult[]> {
  const results: EnrichmentResult[] = [];
  for (const item of items) {
    const outcome = await enrichOne(item, ctx);
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
  const inputHash = sha256Json(item);
  const itemRef: LineageArtifactRef = { kind: "IntelItem", id: item.intel_id, sha256: inputHash };
  const inputParent = ctx.lineage_parent_by_intel_id?.[item.intel_id];
  const causation = ctx.causation_by_intel_id?.[item.intel_id] ?? null;
  const fallbackRefs: LineageArtifactRef[] = [];
  const emit = makeEmitter(ctx, fallbackRefs, itemRef, inputParent, causation);

  // F1：论文关联
  const f1Started = nowIso();
  const f1FallbackStart = fallbackRefs.length;
  let papersRes: Awaited<ReturnType<typeof searchPapers>>;
  try {
    papersRes = await searchPapers(item.title, { offline: ctx.offline, fetchImpl: ctx.fetchImpl, traceId, emit });
  } catch {
    await ctx.bus?.recordLineage({
      trace_id: traceId, parent_lineage_ids: inputParent ? [inputParent] : [], causation_id: causation,
      stage: "enrich.f1", operation_version: "f1-papers.v1", status: "failed", started_at: f1Started,
      input_refs: [itemRef], error: "paper enrichment failed",
    });
    throw new Error("F1 富化失败；lineage 已记录 trace_id=" + traceId + " intel_id=" + item.intel_id);
  }
  const paperPayload = papersPayload(item.intel_id, papersRes.papers);
  const papersEnv = await ctx.bus?.publish("enrich.papers", paperPayload, { trace_id: traceId, causation_id: causation });
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

  // Optional F1 StepPlan advice: sidecar only; never changes PaperLink scores, order, or published EnrichmentResult.
  if (ctx.paperReviewer && ctx.bus && !papersRes.degraded_to && shouldAskPaperReviewer(papersRes.papers)) {
    const candidates = papersRes.papers.map((paper) => ({
      paper_id: paper.paper_id,
      title: paper.title,
      ...(paper.year !== undefined ? { year: paper.year } : {}),
      rule_relevance_score: paper.relevance_score,
      evidence_terms: paper.evidence_terms ?? [],
    }));
    const projection = { query: item.title, candidates };
    const projectionHash = sha256Json(projection);
    const reviewStarted = nowIso();
    let reviewOutcome: PaperReviewOutcome;
    let reviewFailed = false;
    try {
      const reviewerPapers = papersRes.papers.map((paper) => ({ ...paper, ...(paper.evidence_terms ? { evidence_terms: [...paper.evidence_terms] } : {}) }));
      reviewOutcome = await ctx.paperReviewer({ trace_id: traceId, intel_id: item.intel_id, query: item.title, papers: reviewerPapers });
    } catch {
      reviewFailed = true;
      await ctx.bus.recordLineage({
        trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
        causation_id: papersEnv?.event_id ?? causation, stage: "enrich.f1_stepfun_advisory", operation_version: "stepfun.f1-advisory.v1", status: "degraded", started_at: reviewStarted,
        input_refs: [{ kind: "F1PaperReviewProjection", id: item.intel_id, sha256: projectionHash }],
        decision: { fallback_to: "rule-ranked-papers", reason: "StepPlan review failed; deterministic F1/F4/F6 outputs remain unchanged" },
        error: "paper review request failed; source text omitted",
      });
      await degrade({
        layer: "L3", trigger: "StepPlan F1 advisory failed; deterministic paper results retained", degradedOf: "rule-ranked-papers", traceId,
        label: "StepPlan 论文建议不可用；F1 规则结果未改变", recoveryHint: "检查 planner provider/key；不会改写论文来源、相关分或 F6 总分。",
        emit: async (event) => emit(event),
      });
      reviewOutcome = { status: "abstained", reason: "review request failed" };
    }
    if (!reviewFailed) {
      const candidateIds = new Set(papersRes.papers.map((paper) => paper.paper_id));
      if (reviewOutcome.status === "suggested" && (reviewOutcome.paper_ids.length < 1 || reviewOutcome.paper_ids.length > candidates.length || new Set(reviewOutcome.paper_ids).size !== reviewOutcome.paper_ids.length || reviewOutcome.paper_ids.some((id) => !candidateIds.has(id)) || !Number.isFinite(reviewOutcome.confidence) || reviewOutcome.confidence < 0.8 || reviewOutcome.confidence > 1)) {
        reviewOutcome = { status: "abstained", reason: "StepPlan paper suggestion failed candidate/threshold validation", model_id: reviewOutcome.model_id };
      }
      const suggested = reviewOutcome.status === "suggested" ? reviewOutcome : undefined;
      const suggestionRefs = suggested
        ? suggested.paper_ids.map((paperId) => ({ kind: "PaperReviewSuggestion", id: paperId, sha256: sha256Json({ paper_id: paperId, confidence: suggested.confidence }) }))
        : [];
      await ctx.bus.recordLineage({
        trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
        causation_id: papersEnv?.event_id ?? causation, stage: "enrich.f1_stepfun_advisory", operation_version: "stepfun.f1-advisory.v1", status: "review", started_at: reviewStarted,
        input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: inputHash }, { kind: "F1PaperReviewProjection", id: item.intel_id, sha256: projectionHash }],
        output_refs: suggestionRefs,
        execution: reviewOutcome.model_id ? { provider: "stepplan", model_id: reviewOutcome.model_id, model_version: "unversioned-api" } : { component_version: "stepfun.f1-advisory.v1" },
        decision: { reason: reviewOutcome.status === "suggested" ? "StepPlan ranking is advisory only; F1 scores/order and published EnrichmentResult remain rule-derived" : "StepPlan F1 advisory abstained: " + reviewOutcome.reason, review_required: true },
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
    sources = ctx.scoreSources ?? (await loadScoreSourcesFromRawRefs(item));
    score = await assessScore(item, { sources, kevSet: ctx.kevSet, offline: ctx.offline, fetchImpl: ctx.fetchImpl, traceId, emit });
  } catch {
    await ctx.bus?.recordLineage({
      trace_id: traceId, parent_lineage_ids: [f1Lineage?.lineage_id, inputParent].filter((id): id is string => Boolean(id)),
      causation_id: papersEnv?.event_id ?? causation,
      stage: "enrich.f4", operation_version: "f4-cvss.v1", status: "failed", started_at: f4Started,
      input_refs: [itemRef], error: "score assessment failed",
    });
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
      trace_id: traceId, causation_id: papersEnv?.event_id ?? causation,
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
