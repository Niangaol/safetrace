/**
 * 富化覆盖率审计（纯函数，零 IO）——回答三件事：
 *   1) 现在到底覆盖了多少（按 sidecar 真实状态算，不按 pending 计数）；
 *   2) 没覆盖的卡在什么原因上（结构性天花板 vs 还可再试）；
 *   3) 还要不要继续跑（目标未达且仍有推进空间才继续）。
 *
 * 为什么需要它：planPendingEnrichment 的 pending 计数不会因某个维度成功而下降
 * （空结果带 24h 退避，条目仍算“有待办维度”），所以它不能当进度指标用。
 */
import type { EnrichmentDimension, EnrichmentDimensionState, IntelItem } from "@safetrace/shared";

export const DIMENSIONS: readonly EnrichmentDimension[] = ["paper", "cvss", "epss"];
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
  covered: number
  uncovered: number
  coverage: number
  target: number
  targetMet: boolean
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
  for (const item of input.items) {
    const entry = byItem.get(item.intel_id)!
    for (const dimension of DIMENSIONS) {
      const state = entry.states.get(dimension)
      if (!state) { byDimension[dimension].absent++; continue }
      byDimension[dimension][state.status]++
      if (state.status === "live") dimensionLiveItems[dimension]++
    }
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
  const progressPossible = uncoveredByReason["no-state"] > 0 || uncoveredByReason["retry-due"] > 0 || uncoveredByReason["epss-failed"] > 0 || uncoveredByReason["paper-failed"] > 0
  const nextActions: string[] = []
  if (uncoveredByReason["no-state"] > 0) nextActions.push(uncoveredByReason["no-state"] + " 条从未跑过富化：先跑一轮全量")
  if (uncoveredByReason["epss-failed"] > 0) nextActions.push(uncoveredByReason["epss-failed"] + " 条 EPSS 传输失败：恢复外网后重试")
  if (uncoveredByReason["paper-failed"] > 0) nextActions.push(uncoveredByReason["paper-failed"] + " 条论文检索失败：检查 arXiv 连通后重试")
  if (!progressPossible) nextActions.push("剩余条目均为结构性缺口（本地无 NVD 评分源 / 上游暂无数据），继续跑也不会提升覆盖率")
  return { accepted, covered, uncovered: accepted - covered, coverage, target, targetMet: coverage >= target, byDimension, dimensionLiveItems, uncoveredByReason, progressPossible, nextActions }
}
