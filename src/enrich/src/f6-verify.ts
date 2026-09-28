/**
 * F6 富化收口：维度枚举 + 多源分值冲突仲裁 + enrichment_score。
 *
 * 纪律：
 * - paper/cvss 是 P0 必做维度，按实际产出枚举进 completed/failed
 * - conflicts 是审计信息：EnrichmentResult.json（D1 冻结）additionalProperties:false，
 *   故只随内存返回值（EnrichmentOutcome）传递，index.ts 发布到总线前会剥离，保证信封契约纯净
 * - enrichment_score = 维度完整度 * 0.6 + 证据覆盖率 * 0.4（纯函数 computeEnrichmentScore）
 */
import { SCHEMA_VERSION, nowIso } from "@safetrace/shared";
import type { Dimension, EnrichmentResult, IntelItem, PaperLink, ScoreAssessment, ScoreSource } from "@safetrace/shared";
import { SCORE_AUTHORITY, type ScoreSourceInput } from "./f4-cvss.js";

export type { ScoreSourceInput } from "./f4-cvss.js";

/** P0 必做维度（paper / cvss；asset/poc/remediation/triage 未落地，不枚举进 completed/failed）。 */
export const REQUIRED_DIMENSIONS: readonly Dimension[] = ["paper", "cvss"];

export interface ScoreConflictValue {
  source: ScoreSource;
  score: number;
}

export interface ScoreConflict {
  field: "cvss_v3_base";
  values: ScoreConflictValue[];
  resolved: boolean;
  /** resolved=true 时必须写明"采用哪源、为何"。 */
  rationale?: string;
}

/** 内存侧完整产出（带 conflicts 审计；总线侧发布前剥离为契约纯净 EnrichmentResult）。 */
export interface EnrichmentOutcome extends EnrichmentResult {
  conflicts: ScoreConflict[];
}

export interface SummarizeInput {
  papers?: PaperLink[];
  scoreAssessment?: ScoreAssessment | null;
  /** 实际参与仲裁的多源分值（含被采用源；用于旁证覆盖度与冲突明细） */
  otherScores?: ScoreSourceInput[];
}

/** 加权公式（可测纯函数）：dimsCompleted 为已完成维度数，evidenceRatio 为证据覆盖率（0-1）。 */
export function computeEnrichmentScore(dimsCompleted: number, evidenceRatio: number): number {
  const dims = clamp01(dimsCompleted / REQUIRED_DIMENSIONS.length);
  const evidence = clamp01(evidenceRatio);
  return round2(0.6 * dims + 0.4 * evidence);
}

/**
 * 证据覆盖率（0-1）：论文证据与分值证据各占一半。
 * - 论文证据：带 evidence_terms 的论文占比（全无证据词或无论文均记 0）
 * - 分值证据：按 otherScores（调用方传入全部参与仲裁的来源，含被采用源）计——
 *   >=2 个来源（有旁证）记 1，仅 1 个来源记 0.6，无来源记 0
 * 注：多源分差未仲裁由 conflicts 记录，不在这条加权里藏。
 */
export function computeEvidenceRatio(
  papers: PaperLink[] | undefined,
  _score: ScoreAssessment | null | undefined,
  otherScores: ScoreSourceInput[] | undefined,
): number {
  const list = papers ?? [];
  const withTerms = list.filter((p) => (p.evidence_terms?.length ?? 0) > 0).length;
  const paperEvidence = list.length > 0 ? withTerms / list.length : 0;
  const sourceCount = otherScores?.length ?? 0;
  const scoreEvidence = sourceCount >= 2 ? 1 : sourceCount === 1 ? 0.6 : 0;
  return round2((paperEvidence + scoreEvidence) / 2);
}

/** 收口：产出 EnrichmentResult（内存侧附 conflicts）。 */
export function summarizeEnrichment(item: IntelItem, input: SummarizeInput): EnrichmentOutcome {
  const papers = input.papers ?? [];
  const score = input.scoreAssessment ?? null;
  const others = input.otherScores ?? [];

  const dimensions_completed: Dimension[] = [];
  const dimensions_failed: Dimension[] = [];
  for (const dim of REQUIRED_DIMENSIONS) {
    const done = dim === "paper" ? papers.length > 0 : score !== null;
    (done ? dimensions_completed : dimensions_failed).push(dim);
  }

  return {
    intel_id: item.intel_id,
    dimensions_completed,
    dimensions_failed,
    artifacts: {
      ...(papers.length > 0 ? { papers } : {}),
      ...(score ? { score_assessment: score } : {}),
    },
    enrichment_score: computeEnrichmentScore(dimensions_completed.length, computeEvidenceRatio(papers, score, others)),
    completed_at: nowIso(),
    schema_version: SCHEMA_VERSION,
    conflicts: buildConflicts(score, others),
  };
}

/** 多源分值差异 -> conflicts（数值不同才记录；同源去重；resolved=true 时 rationale 写明采用源与理由）。 */
export function buildConflicts(score: ScoreAssessment | null, others: ScoreSourceInput[]): ScoreConflict[] {
  const seen = new Set<ScoreSource>();
  const values: ScoreConflictValue[] = [];
  const push = (source: ScoreSource, value: number | undefined): void => {
    if (value === undefined || seen.has(source)) return;
    seen.add(source);
    values.push({ source, score: value });
  };
  if (score) push(score.source_of_score, score.cvss_v3_base);
  for (const o of others) push(o.source_of_score, o.cvss_v3_base);

  if (values.length < 2) return [];
  const distinct = new Set(values.map((v) => v.score));
  if (distinct.size <= 1) return []; // 多源分值一致：无冲突

  if (score) {
    const why =
      score.source_of_score === "system_derived"
        ? `系统派生（${score.derived_reason ?? "未说明"}）`
        : `权威序 ${SCORE_AUTHORITY.join(" > ")} 中 ${score.source_of_score} 优先级最高`;
    return [
      {
        field: "cvss_v3_base",
        values,
        resolved: true,
        rationale: `采用 ${score.source_of_score} 的 ${score.cvss_v3_base} 分：${why}；差异源仅作旁证，不改写分值`,
      },
    ];
  }
  // 未产出最终评分（无可用来源）：分差未仲裁，cvss 维度记失败
  return [
    {
      field: "cvss_v3_base",
      values,
      resolved: false,
      rationale: "未产出最终评分（无可用评分来源），多源分差未仲裁；已由 dimensions_failed 显式记 cvss 失败",
    },
  ];
}

function clamp01(x: number): number {
  if (!Number.isFinite(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}
