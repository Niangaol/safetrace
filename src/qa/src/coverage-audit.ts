/**
 * 富化覆盖率审计（纯函数，零 IO）——回答三件事：
 *   1) 现在到底覆盖了多少（按 sidecar 真实状态算，不按 pending 计数）；
 *   2) 没覆盖的卡在什么原因上（结构性天花板 vs 还可再试）；
 *   3) 还要不要继续跑（目标未达且仍有推进空间才继续）。
 *
 * 为什么需要它：planPendingEnrichment 的 pending 计数不会因某个维度成功而下降
 * （空结果带 24h 退避，条目仍算“有待办维度”），所以它不能当进度指标用。
 *
 * 口径三分（互不等价，报告时必须并列给出，禁止只报一个数）：
 *   A any-dimension-live：任一维度 live 即算覆盖（历史 headline 口径，最宽松）；
 *   B required-dimensions-live：覆盖必备维度（cvss）live 才算覆盖——target 达标线
 *     按这一把尺判定（2026-10-09 用户决策：paper 降为可选增强，不再进达标线）；
 *   C per-dimension-live：分维度各自算 live 占比（含可选维度 paper）。
 * 另有一个更严的 D 口径不在本纯函数能力范围内：仪表盘/QA 引用要求 paper/cvss 的
 * artifact 与原始 NVD/CNA 报文逐字匹配且血缘完整（readLiveKnowledgeView 投影验证），
 * 需要读取原始 payload（IO）。D 与 B/C 的差集即“sidecar 说 live 但投影不认”的条目，
 * 实测差集根因与覆盖率口径见 docs/TUTORIAL.md §7。
 */
import type { EnrichmentDimension, EnrichmentDimensionState, IntelItem } from "@safetrace/shared";

export const DIMENSIONS: readonly EnrichmentDimension[] = ["paper", "cvss", "epss"];
/**
 * 覆盖必备维度：cvss。2026-10-09 用户决策“paper 作为可选项”——论文检索对 KEV 老条目
 * 上游无匹配是结构性现实（arXiv 不收录厂商标题原文），拿它当达标线只会得到恒为 0
 * 的假指标。注意这与 f6-verify 的 REQUIRED_DIMENSIONS（paper+cvss）不是一件事：
 * 那边是富化完成度契约（EnrichmentResult.json 已冻结，不动），这边是覆盖率达标线。
 */
export const REQUIRED_LIVE_DIMENSIONS: readonly EnrichmentDimension[] = ["cvss"];
/** 可选增强维度：命中算赚到，缺失不影响达标判定，也不触发零 live 预警。 */
export const OPTIONAL_LIVE_DIMENSIONS: readonly EnrichmentDimension[] = ["paper"];
/** 辅助维度：单独跟踪，不进达标线（EPSS 由 FIRST 单点可得，作覆盖率指标没有区分度）。 */
export const AUXILIARY_LIVE_DIMENSIONS: readonly EnrichmentDimension[] = ["epss"];
// 维度分类必须穷尽：新增维度忘了归类会在导入期炸出来，而不是 silently 不进任何口径
{
  const classified = new Set<string>([...REQUIRED_LIVE_DIMENSIONS, ...OPTIONAL_LIVE_DIMENSIONS, ...AUXILIARY_LIVE_DIMENSIONS]);
  const missing = DIMENSIONS.filter(d => !classified.has(d));
  if (missing.length > 0 || classified.size !== DIMENSIONS.length) throw new Error("覆盖维度分类不穷尽：未归类 " + missing.join("/") + "；请更新 REQUIRED/OPTIONAL/AUXILIARY_LIVE_DIMENSIONS")
}
export type UncoveredReason =
  | "no-state"
  | "retry-due"
  | "epss-empty-backoff"
  | "epss-failed"
  | "epss-degraded"
  | "cvss-no-local-source"
  | "cvss-degraded"
  | "paper-empty-backoff"
  | "paper-failed";
export interface DimensionCounts { live: number; empty: number; failed: number; degraded: number; unknown: number; absent: number }
export interface CoverageAudit {
  accepted: number
  /** 口径 A：任一维度 live 的条目数。 */
  covered: number
  uncovered: number
  /** 口径 A 比率（covered/accepted）。历史 headline 数字，最宽松，禁止单独引用。 */
  coverage: number
  target: number
  targetMet: boolean
  /** 口径 B：覆盖必备维度（cvss）live 的条目数（paper 为可选，不计入）。 */
  coveredRequired: number
  /** 口径 B 比率（coveredRequired/accepted）。target 达标线按这把尺判定。 */
  coverageRequired: number
  /** 口径 C：分维度 live 占比（live/accepted；accepted=0 时为 0）。 */
  dimensionLiveRatio: Record<EnrichmentDimension, number>
  byDimension: Record<EnrichmentDimension, DimensionCounts>
  dimensionLiveItems: Record<EnrichmentDimension, number>
  uncoveredByReason: Record<UncoveredReason, number>
  /** 继续跑还能不能提升覆盖率（结构性天花板时为 false）。 */
  progressPossible: boolean
  nextActions: string[]
}
const REASONS: readonly UncoveredReason[] = ["no-state", "retry-due", "epss-empty-backoff", "epss-failed", "epss-degraded", "cvss-no-local-source", "cvss-degraded", "paper-empty-backoff", "paper-failed"];
function emptyReasonCounts(): Record<UncoveredReason, number> {
  return Object.fromEntries(REASONS.map(r => [r, 0])) as Record<UncoveredReason, number>
}
function emptyDimensionCounts(): DimensionCounts { return { live: 0, empty: 0, failed: 0, degraded: 0, unknown: 0, absent: 0 } }
/** 单维度未覆盖原因；state.status==="empty" 对 cvss 即“本地无可用评分源”（结构性）。 */
function classify(state: EnrichmentDimensionState | undefined, dimension: EnrichmentDimension): UncoveredReason {
  if (!state) return "no-state"
  if (state.status === "failed") return dimension === "epss" ? "epss-failed" : "paper-failed"
  if (state.status === "degraded") return dimension === "epss" ? "epss-degraded" : "cvss-degraded"
  if (state.status === "empty") return dimension === "epss" ? "epss-empty-backoff" : dimension === "cvss" ? "cvss-no-local-source" : "paper-empty-backoff"
  return "retry-due"
}
export function auditCoverage(input: { items: readonly IntelItem[]; states: readonly EnrichmentDimensionState[]; now?: Date; target?: number }): CoverageAudit {
  const now = input.now ?? new Date()
  const target = input.target ?? 0.9
  const known = new Set(input.items.map(i => i.intel_id))
  const byItem = new Map<string, { states: Map<EnrichmentDimension, EnrichmentDimensionState>; live: Set<EnrichmentDimension> }>()
  for (const item of input.items) byItem.set(item.intel_id, { states: new Map(), live: new Set() })
  for (const state of input.states) {
    const entry = byItem.get(state.intel_id)
    if (!entry || !known.has(state.intel_id)) continue
    entry.states.set(state.dimension, state)
    if (state.status === "live") entry.live.add(state.dimension)
  }
  const byDimension: Record<EnrichmentDimension, DimensionCounts> = { paper: emptyDimensionCounts(), cvss: emptyDimensionCounts(), epss: emptyDimensionCounts() }
  const dimensionLiveItems: Record<EnrichmentDimension, number> = { paper: 0, cvss: 0, epss: 0 }
  const uncoveredByReason = emptyReasonCounts()
  let covered = 0
  let coveredRequired = 0
  for (const item of input.items) {
    const entry = byItem.get(item.intel_id)!
    for (const dimension of DIMENSIONS) {
      const state = entry.states.get(dimension)
      if (!state) { byDimension[dimension].absent++; continue }
      byDimension[dimension][state.status]++
      if (state.status === "live") dimensionLiveItems[dimension]++
    }
    if (REQUIRED_LIVE_DIMENSIONS.every(d => entry.live.has(d))) coveredRequired++
    if (entry.live.size > 0) { covered++; continue }
    // 未覆盖：按“最可能推进的原因”归类。只有全部维度都没有状态才是“从未跑过”；
    // 已跑过的维度里，可重试原因优先于结构性缺口。
    const present = DIMENSIONS.filter(d => entry.states.has(d))
    const ranked = present.map(d => classify(entry.states.get(d), d))
    const actionable = ranked.find(r => r === "retry-due" || r === "epss-failed" || r === "paper-failed")
    const structural = ranked.find(r => r === "cvss-no-local-source" || r === "epss-empty-backoff" || r === "paper-empty-backoff" || r === "epss-degraded" || r === "cvss-degraded")
    uncoveredByReason[present.length === 0 ? "no-state" : (actionable ?? structural ?? "no-state")]++
  }
  const accepted = input.items.length
  const coverage = accepted === 0 ? 0 : covered / accepted
  const coverageRequired = accepted === 0 ? 0 : coveredRequired / accepted
  const dimensionLiveRatio = Object.fromEntries(DIMENSIONS.map(d => [d, accepted === 0 ? 0 : dimensionLiveItems[d] / accepted])) as Record<EnrichmentDimension, number>
  const progressPossible = uncoveredByReason["no-state"] > 0 || uncoveredByReason["retry-due"] > 0 || uncoveredByReason["epss-failed"] > 0 || uncoveredByReason["paper-failed"] > 0
  const nextActions: string[] = []
  if (uncoveredByReason["no-state"] > 0) nextActions.push(uncoveredByReason["no-state"] + " 条从未跑过富化：先跑一轮全量")
  if (uncoveredByReason["epss-failed"] > 0) nextActions.push(uncoveredByReason["epss-failed"] + " 条 EPSS 传输失败：恢复外网后重试")
  if (uncoveredByReason["paper-failed"] > 0) nextActions.push(uncoveredByReason["paper-failed"] + " 条论文检索失败：检查 arXiv 连通后重试")
  // headline 口径 A 会被单一维度抬高：必备维度 live 为 0 时必须显式提示，禁止只报口径 A
  const zeroLiveRequired = REQUIRED_LIVE_DIMENSIONS.filter(d => dimensionLiveItems[d] === 0)
  if (zeroLiveRequired.length > 0) nextActions.push("必备维度 " + zeroLiveRequired.join("/") + " live 为 0：headline（口径 A）被其他维度抬高，真实深度看口径 B/C；与仪表盘投影验证口径的差异见 docs/TUTORIAL.md §7 富化覆盖率口径")
  if (!progressPossible) nextActions.push("剩余条目均为结构性缺口（本地无 NVD 评分源 / 上游暂无数据），继续跑也不会提升覆盖率")
  // target 达标线按口径 B（必备维度）判定：口径 A 达标但必备维度未达标时，继续跑仍有意义
  const targetMet = coverageRequired >= target
  return { accepted, covered, uncovered: accepted - covered, coverage, target, targetMet, coveredRequired, coverageRequired, dimensionLiveRatio, byDimension, dimensionLiveItems, uncoveredByReason, progressPossible, nextActions }
}
