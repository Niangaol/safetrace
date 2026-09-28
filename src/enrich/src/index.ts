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
import { nextId, nowIso, SCHEMA_VERSION } from "@safetrace/shared";
import type { EventBus, FallbackEvent, IntelItem, EnrichmentResult } from "@safetrace/shared";
import {
  assessScore,
  loadScoreSourcesFromRawRefs,
  type HttpFetcher,
  type ScoreSourceInput,
} from "./f4-cvss.js";
import { searchPapers } from "./f1-papers.js";
import {
  computeEnrichmentScore,
  type EnrichmentOutcome,
  type ScoreConflict,
  summarizeEnrichment,
} from "./f6-verify.js";

export * from "./f4-cvss.js";
export * from "./f1-papers.js";
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
  /** 降级观察者（FallbackEvent，与 fallback.events 同口径；前端横幅据此渲染）。 */
  onDegrade?: (event: FallbackEvent) => void | Promise<void>;
  /** 多源分差观察者（conflicts 审计信息，不在 EnrichmentResult 契约内）。 */
  onConflict?: (conflict: ScoreConflict, intelId: string) => void | Promise<void>;
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

async function enrichOne(item: IntelItem, ctx: EnrichContext): Promise<EnrichmentOutcome> {
  const traceId = ctx.traceId ?? nextId("tr");
  const emit = makeEmitter(ctx);

  // F1：论文关联
  const papersRes = await searchPapers(item.title, {
    offline: ctx.offline,
    fetchImpl: ctx.fetchImpl,
    traceId,
    emit,
  });
  const papersEnv = await ctx.bus?.publish("enrich.papers", papersPayload(item.intel_id, papersRes.papers), {
    trace_id: traceId,
  });

  // F4：分值仲裁 + EPSS 增强（离线/fetch 失败已在 assessScore 内降级留痕）
  const sources = ctx.scoreSources ?? (await loadScoreSourcesFromRawRefs(item));
  const score = await assessScore(item, {
    sources,
    kevSet: ctx.kevSet,
    offline: ctx.offline,
    fetchImpl: ctx.fetchImpl,
    traceId,
    emit,
  });

  // F6：收口（内存侧带 conflicts；总线侧发布剥离后的契约纯净 payload）
  const outcome = summarizeEnrichment(item, {
    papers: papersRes.papers,
    scoreAssessment: score,
    otherScores: sources,
  });
  for (const conflict of outcome.conflicts) {
    await ctx.onConflict?.(conflict, item.intel_id);
  }
  await ctx.bus?.publish("enrich.items", toContractPayload(outcome), {
    trace_id: traceId,
    causation_id: papersEnv?.event_id ?? null,
  });
  return outcome;
}

/** 降级统一出口：有总线则上 fallback.events，同时通知观察者（两者皆无也已在 degrade() 内登记）。 */
function makeEmitter(ctx: EnrichContext): (event: FallbackEvent) => void | Promise<void> {
  return (event: FallbackEvent) => {
    if (ctx.bus) void ctx.bus.publish("fallback.events", event);
    if (ctx.onDegrade) return ctx.onDegrade(event);
    return undefined;
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
