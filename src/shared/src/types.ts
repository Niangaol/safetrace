/**
 * 契约 TS 镜像 —— 唯一事实来源是 contracts/schemas/*.json（D1 冻结）。
 * 纪律：改语义必须走 contract/ PR 三线 sign-off；本文件只做 1:1 类型映射，
 * 运行期校验由 schema.ts（ajv 风格子集）与 scripts/validate_contracts.py 兜底。
 */
export const SCHEMA_VERSION = "1.0";

export type SourceType =
  | "nvd_cve" | "cve_org" | "ghsa" | "osv" | "vendor_advisory"
  | "security_community" | "security_blog" | "poec_source" | "kev"
  | "standard_policy" | "paper";

export type ContentType = "json" | "html" | "xml" | "text" | "pdf";

export interface RawDoc {
  source_id: string;
  source_type: SourceType;
  external_id: string;
  url: string;
  fetched_at: string;
  content_type: ContentType;
  payload_ref: string;
  http_etag?: string;
  parse_warnings?: string[];
}

export interface Entities {
  product: string | null;
  vendor: string | null;
  version_range: string[];
  cwe: string[];
  cpes: string[];
}

export interface IntelItem {
  intel_id: string;
  cve_ids: string[];
  ghsa_ids?: string[];
  osv_ids?: string[];
  aliases?: string[];
  source_ids: string[];
  title: string;
  summary?: string;
  published_at: string;
  first_seen_at: string;
  entities: Entities;
  raw_refs: string[];
  source_reliability: number;
  schema_version: string;
}

export type Dimension = "paper" | "asset" | "poc" | "cvss" | "remediation" | "triage";

export type ScoreSource = "nvd" | "cna" | "ghsa" | "adp" | "system_derived";

export interface PaperLink {
  paper_id: string;
  source: "arxiv" | "s2";
  title: string;
  year?: number;
  venue?: string;
  relevance_score: number;
  confidence: number;
  evidence_terms?: string[];
}

export interface ScoreAssessment {
  cvss_v3_vector: string;
  cvss_v3_base: number;
  source_of_score: ScoreSource;
  derived_reason?: string;
  epss_score?: number;
  epss_percentile?: number;
  kev_flag?: boolean;
  exploit_maturity?: string;
  impact_summary?: string;
  confidence?: number;
}

export interface EnrichmentResult {
  intel_id: string;
  dimensions_completed: Dimension[];
  dimensions_failed: Dimension[];
  artifacts: { papers?: PaperLink[]; score_assessment?: ScoreAssessment };
  enrichment_score: number;
  completed_at: string;
  schema_version: string;
}

export type DecisionKind = "y5_triage" | "q1_route" | "q3_sufficiency" | "dq_verdict";
export type QuestionType = "choice" | "score" | "noul";
export type DecidedBy = "jev_api" | "llm_fallback" | "rule_fallback" | "cache";

export interface TypedQuestion {
  q_id: string;
  type: QuestionType;
  options?: string[];
  rubric?: string;
  cardinality_max?: number;
}

export interface DecisionRequest {
  decision_id: string;
  kind: DecisionKind;
  state: Record<string, unknown>;
  questions: TypedQuestion[];
  trace_id: string;
  schema_version: string;
}

export interface DecisionReply {
  decision_id: string;
  kind: DecisionKind;
  decision: { choice?: string; score?: number; abstain?: boolean };
  calibrated_prob: number;
  decided_by: DecidedBy;
  fallback_reason?: string;
  schema_version: string;
}

export type DocType = "vuln_advisory" | "vendor_advisory" | "paper" | "standard" | "policy" | "enrichment";

export interface RetrievalRequest {
  query_id: string;
  query_text: string;
  top_k: number;
  doc_types?: DocType[];
  cve_ids?: string[];
  published_after?: string;
  min_quality?: number;
  trace_id: string;
  schema_version: string;
}

export interface Provenance {
  url: string;
  section: string;
  page?: number;
  sha256?: string;
}

export interface EvidenceChunk {
  chunk_id: string;
  doc_type: DocType;
  text: string;
  score_dense?: number;
  score_sparse?: number;
  score_rerank?: number;
  quality_score?: number;
  provenance: Provenance;
}

export interface RetrievalResponse {
  query_id: string;
  chunks: EvidenceChunk[];
  retrieval_ms: number;
  embedder_model_id: string;
  degraded_to?: string;
  trace_id: string;
  schema_version: string;
}

export type ToolKind = "source_adapter" | "enrich_dimension" | "retriever" | "decision" | "selfheal";
export type ToolState = "staging" | "canary" | "active" | "retired";

export interface ToolPermissions {
  network: boolean;
  filesystem: "none" | "read" | "workspace-write";
  exec: boolean;
}

export interface ToolRegistration {
  tool_id: string;
  version: string;
  kind: ToolKind;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  permissions: ToolPermissions;
  state: ToolState;
  mcp_projection?: boolean;
  sha256: string;
  registered_at: string;
}

/* ---------- events.md 内联契约镜像 ---------- */

export type DqVerdict = "pass" | "degrade" | "review" | "quarantine";
export type DqItemKind = "intel" | "enriched";
export type DqFlag =
  | "ts_no_tz" | "reject_status" | "poc_dead_link" | "key5_missing"
  | "boilerplate" | "multi_id_mismatch";

export interface QualityVerdict {
  item_id: string;
  item_kind: DqItemKind;
  quality_score: number;
  dimension_scores: {
    structure: number; completeness: number; consistency: number;
    timeliness: number; sourcing: number;
  };
  flags: DqFlag[];
  verdict: DqVerdict;
  quarantine_ref?: string;
  reviewer?: string;
  reviewed_at?: string;
  gate_version: string;
}

export type TriageLevel = "P0" | "P1" | "P2" | "P3";
export type TriageRoute = "full_enrich" | "lite_enrich" | "index_only";

export interface TriageOrder {
  intel_id: string;
  level: TriageLevel;
  reason: string;
  route: TriageRoute;
  enrich_plan: Array<{ dimension: Dimension; required: boolean }>;
  sla_deadline: string;
}

export interface QueryTurn {
  session_id: string;
  turn_id: string;
  text: string;
  history?: Array<{ role: "user" | "assistant"; text: string }>;
}

export interface Answer {
  session_id: string;
  turn_id: string;
  text_md: string;
  citations: Array<{ chunk_id: string; url: string }>;
  reasoning_chain: string[];
  confidence: number;
  abstained: boolean;
  degraded_to?: string;
}

export type FallbackLayer = "L1" | "L2" | "L3" | "L4";

export interface FallbackEvent {
  event_id: string;
  layer: FallbackLayer;
  trigger: string;
  action_taken: string;
  degraded_of: string;
  user_visible: boolean;
  degraded_state: { label: string; since: string; detail_ref: string };
  recovery_hint?: string;
  trace_id: string;
}
