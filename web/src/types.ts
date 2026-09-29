// 与 src/aiintel/api/routers/*.py 的实际响应体对齐
export interface VulnItem {
  id: string
  cve_id: string
  ghsa_id: string | null
  title: string
  description?: string
  severity: string
  cvss_score: number | null
  cvss_vector: string | null
  /** EPSS 被利用概率（0~1）。动态优先级权重 0.45，见 services/triage.py */
  epss?: number | null
  /** 是否已列入 CISA KEV（在野利用）。这两个信号决定 triage 的排序，必须可见 */
  kev?: boolean
  /** KEV 官方强制修复截止日（YYYY-MM-DD），仅 KEV 源提供 */
  kev_due_date?: string | null
  cwe: string[]
  cpe: string[]
  ai_risk_category: string | null
  exploit_status: string | null
  published_at: string | null
  fetched_at: string | null
  collect_latency_seconds: number | null
  source_count: number
  enriched: boolean
  summary?: string
  related?: { papers: unknown[]; pocs: unknown[] }
}

export interface Paged<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface Evidence {
  /** 维度内稳定编号（ev-1、ev-2…），value 里的 evidence_ref 回指它 */
  evidence_id?: string
  source: string
  url: string | null
  snippet: string
  fetched_at: string | null
  raw_item_id?: string | null
}

export interface Enrichment {
  dimension: string
  value: Record<string, unknown>
  /** 本结论实际依据的数据源（赛题硬要求"每条富化带 source"） */
  source?: string[]
  evidence: Evidence[]
  confidence: number
  model: string
  agent: string
  version: number
  /** true 表示含预置数据，必须在 UI 标注 */
  mock?: boolean
  /** 非空即降级产物：cache | fixture | rule | mock | local */
  degraded_to?: string | null
  degraded_reason?: string
  /** 仅 consistency 维度产出 */
  quality_score?: number | null
  trace_id?: string | null
  created_at: string | null
}

export interface GraphNode {
  id: string
  type: string
  label?: string
}

export interface GraphEdge {
  src: string
  rel: string
  dst: string
  type?: string
}

export interface EvidenceResponse {
  enrichments: Enrichment[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
}

export interface Citation {
  id: string
  title: string
  url: string
  score: number
}

export interface Watermark {
  source: string
  last_sync_at: string | null
  last_full_sync_at: string | null
  last_published_at: string | null
  items_last_run: number
  success: boolean
  error: string | null
}

export interface CollectStatus {
  watermarks: Watermark[]
  queue_depth: number
}

/** GET /metrics/overview 的嵌套结构 */
export interface MetricsOverview {
  collect: {
    raw_items: number
    vulns: number
    merge_ratio: number
    sources: number
  }
  latency: {
    p50_seconds: number | null
    p95_seconds: number | null
    sla_6h_ratio: number | null
  }
  enrich: {
    coverage_ratio: number
    records: number
    dimensions?: number
    degraded_ratio?: number
    per_dimension?: Record<
      string,
      {
        records: number
        coverage_ratio: number
        confidence_avg: number
        degraded_ratio: number
        mock_ratio: number
      }
    >
  }
  knowledge: { chunks: number }
  agents: { runs: number; failed: number }
  cost: {
    total_cny: number
    daily_budget_cny: number
    degraded: boolean
    breakdown: Record<string, number>
  }
}
