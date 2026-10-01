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
  confidence: number | null
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
  data_mode?: 'fixture' | 'live'
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
  data_mode?: 'fixture' | 'live'
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
        confidence_avg: number | null
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

export type IngestSourceState = "live" | "partial" | "fixture" | "no_new_data" | "failed"
export type IngestRunMode = "live" | "mixed" | "fixture" | "no_data"
export interface IngestDiagnosticSource { source_id: string; state: IngestSourceState; raw_docs: number; intel_items: number; detail: string }
export interface IngestDiagnosticFallback { trigger: string; count: number; user_visible: boolean }
export interface IngestDiagnosticCounts {
  raw_docs: number; intel_events: number; unique_intel_ids: number; dq_verdicts: number;
  dq_pass: number; dq_degrade: number; dq_review: number; dq_quarantine: number;
  enrich_items: number; enrich_degraded_items: number; accepted_items: number; enrich_coverage: number | null; fallback_events: number
}
export interface IngestDiagnosticRun {
  trace_id: string; started_at: string; last_activity_at: string; mode: IngestRunMode;
  sources: IngestDiagnosticSource[]; counts: IngestDiagnosticCounts; fallbacks: IngestDiagnosticFallback[]; warnings: string[]
}
export interface IngestDiagnostics {
  generated_at: string; database_available: boolean; database_name: string; nvd_api_key_configured: boolean;
  total_runs: number; latest_run: IngestDiagnosticRun | null;
  recent_runs: Array<Pick<IngestDiagnosticRun, "trace_id" | "started_at" | "last_activity_at" | "mode" | "counts">>; note?: string
}
