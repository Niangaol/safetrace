import { nextId, nowIso, sha256Json } from "@safetrace/shared";
import type { EventBus, LineageArtifactRef } from "@safetrace/shared";
import type { PageFetchResult } from "./firecrawl.js";

export interface AdvisoryCandidate {
  source_url: string;
  title: string;
  summary: string;
  cve_ids: string[];
  confidence: number;
  evidence_quotes: string[];
}
export interface LlmExtractionInput { source_url: string; title: string; text: string }
export type LlmExtractionPort = (input: LlmExtractionInput) => Promise<unknown>;
export type UntrustedTextGate = (input: LlmExtractionInput) => Promise<boolean>;
export type ExtractionResult =
  | { status: "candidate"; extracted_by: "rules" | "llm"; candidate: AdvisoryCandidate; next_step: "DQ1"; trace_id: string; lineage_ids: string[] }
  | { status: "needs_human_review"; reason: string; rule_candidate?: AdvisoryCandidate; review_id?: string; trace_id: string; lineage_ids: string[] };
export interface LlmExecutionMetadata { provider?: string; model_id?: string; model_version?: string; prompt_sha256?: string; config_sha256?: string }

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;
function safeSourceUrl(raw: string): string {
  try { const url = new URL(raw); url.search = ""; url.hash = ""; return url.toString(); } catch { return "[invalid-page-url]"; }
}
function uniqueCves(text: string): string[] {
  return [...new Set((text.match(CVE_RE) ?? []).map((id) => id.toUpperCase()))];
}
function pageTitle(page: Pick<PageFetchResult, "title" | "text">): string {
  return page.title.trim() || page.text.match(/^\s{0,3}#{1,6}\s+(.+)$/m)?.[1]?.trim() || "";
}
function evidenceSentences(text: string): string[] {
  return text.split(/\r?\n+/).flatMap((line) => line.split(/(?<=[。！？.!?])\s+/)).map((line) => line.trim()).filter(Boolean);
}
function rulesCandidate(page: PageFetchResult): AdvisoryCandidate | undefined {
  const title = pageTitle(page);
  const cveIds = uniqueCves(page.text);
  const quote = evidenceSentences(page.text).find((line) => cveIds.some((id) => line.toUpperCase().includes(id)) && line.length >= 20);
  if (!title || cveIds.length === 0 || !quote) return undefined;
  return {
    source_url: safeSourceUrl(page.source_url),
    title,
    summary: quote,
    cve_ids: cveIds,
    confidence: 0.95,
    evidence_quotes: [quote],
  };
}
function objectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function validateLlmDraft(value: unknown, page: PageFetchResult, minimumConfidence: number): AdvisoryCandidate | undefined {
  if (!objectRecord(value)) return undefined;
  const title = value.title;
  const summary = value.summary;
  const confidence = value.confidence;
  const rawCves = value.cve_ids;
  const rawQuotes = value.evidence_quotes;
  if (typeof title !== "string" || title.trim().length === 0 || title.length > 300) return undefined;
  if (typeof summary !== "string" || summary.trim().length === 0 || summary.length > 1500) return undefined;
  if (!Number.isFinite(confidence) || typeof confidence !== "number" || confidence < minimumConfidence || confidence > 1) return undefined;
  if (!page.text.includes(title) && page.title !== title) return undefined;
  if (!Array.isArray(rawCves) || rawCves.length === 0 || rawCves.length > 10) return undefined;
  const cveIds = rawCves.map((id) => typeof id === "string" ? id.toUpperCase() : "");
  if (cveIds.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id) || !page.text.toUpperCase().includes(id))) return undefined;
  if (new Set(cveIds).size !== cveIds.length) return undefined;
  if (!Array.isArray(rawQuotes) || rawQuotes.length === 0 || rawQuotes.length > 5 || rawQuotes.some((quote) => typeof quote !== "string" || quote.trim().length === 0 || !page.text.includes(quote))) return undefined;
  const evidenceQuotes = rawQuotes as string[];
  if (!evidenceQuotes.includes(summary)) return undefined;
  return { source_url: safeSourceUrl(page.source_url), title, summary, cve_ids: cveIds, confidence, evidence_quotes: evidenceQuotes };
}

/**
 * 确定性规则优先；只有调用方同时提供安全门和 MG1 adapter 且门返回 true 才调用 LLM。
 * 本函数不连接云模型，也不发布 IntelItem；未确定内容只返回 needs_human_review。
 */
export async function extractAdvisoryWithFallback(
  page: PageFetchResult,
  options: {
    safety_gate?: UntrustedTextGate;
    llm?: LlmExtractionPort;
    min_llm_confidence?: number;
    bus?: EventBus;
    trace_id?: string;
    parent_lineage_ids?: string[];
    llm_execution?: LlmExecutionMetadata;
  } = {},
): Promise<ExtractionResult> {
  const traceId = options.trace_id ?? page.trace_id;
  const pageUrl = (() => { try { const url = new URL(page.final_url); url.search = ""; url.hash = ""; return url.toString(); } catch { return "[invalid-page-url]"; } })();
  const pageRef: LineageArtifactRef = { kind: "WebPage", id: pageUrl, sha256: page.content_sha256, url: pageUrl };
  const lineageIds = [...(options.parent_lineage_ids ?? page.lineage_ids)];
  let parents = [...lineageIds];
  const record = async (
    stage: string,
    operationVersion: string,
    status: "success" | "degraded" | "rejected" | "review" | "failed",
    inputRefs: LineageArtifactRef[],
    outputRefs: LineageArtifactRef[] = [],
    extras: { started_at?: string; execution?: { component_version?: string; provider?: string; model_id?: string; model_version?: string; config_sha256?: string; prompt_sha256?: string }; decision?: { reason?: string; fallback_to?: string; review_required?: boolean; quality_score?: number }; error?: string } = {},
  ): Promise<string | undefined> => {
    if (!options.bus) return undefined;
    const saved = await options.bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: parents,
      stage,
      operation_version: operationVersion,
      status,
      input_refs: inputRefs,
      output_refs: outputRefs,
      ...extras,
    });
    lineageIds.push(saved.lineage_id);
    parents = [saved.lineage_id];
    return saved.lineage_id;
  };
  const review = async (reason: string, ruleCandidate?: AdvisoryCandidate): Promise<ExtractionResult> => {
    const candidateHash = ruleCandidate ? sha256Json(ruleCandidate) : undefined;
    const reviewLineageId = await record(
      "extract.review_required",
      "manual-review-route.v1",
      "review",
      [pageRef],
      candidateHash ? [{ kind: "ReviewCandidate", id: pageUrl, sha256: candidateHash, url: pageUrl }] : [],
      { decision: { reason, review_required: true } },
    );
    let reviewId: string | undefined;
    if (options.bus && reviewLineageId) {
      reviewId = nextId("rv");
      const reviewCase = {
        review_id: reviewId,
        trace_id: traceId,
        source_url: pageUrl,
        page_sha256: page.content_sha256,
        title: page.title,
        reason,
        ...(candidateHash ? { candidate_sha256: candidateHash } : {}),
        lineage_id: reviewLineageId,
        created_at: nowIso(),
      };
      try {
        await options.bus.enqueueReviewCase(reviewCase);
        await record(
          "extract.review_case_queued",
          "human-review-queue.v1",
          "review",
          [pageRef],
          [{ kind: "ReviewCase", id: reviewId, sha256: sha256Json({ ...reviewCase, title: undefined }) }],
          { decision: { reason: "queued for human review", review_required: true } },
        );
      } catch {
        await record("extract.review_case_enqueue", "human-review-queue.v1", "failed", [pageRef], [], { error: "review queue enqueue failed" });
        throw new Error("could not persist human review case; trace_id=" + traceId);
      }
    }
    return { status: "needs_human_review", reason, ...(ruleCandidate ? { rule_candidate: ruleCandidate } : {}), ...(reviewId ? { review_id: reviewId } : {}), trace_id: traceId, lineage_ids: [...lineageIds] };
  };

  const ruleStarted = nowIso();
  const deterministic = rulesCandidate(page);
  const ruleHash = deterministic ? sha256Json(deterministic) : undefined;
  await record(
    "extract.rules",
    "cve-title-sentence-rules.v1",
    deterministic ? "success" : "degraded",
    [pageRef],
    ruleHash ? [{ kind: "AdvisoryCandidate", id: pageUrl, sha256: ruleHash, url: pageUrl }] : [],
    { started_at: ruleStarted, execution: { component_version: "cve-title-sentence-rules.v1" }, ...(deterministic ? {} : { decision: { reason: "rules could not extract a complete evidence-backed candidate" } }) },
  );
  if (deterministic) return { status: "candidate", extracted_by: "rules", candidate: deterministic, next_step: "DQ1", trace_id: traceId, lineage_ids: [...lineageIds] };

  const input: LlmExtractionInput = { source_url: safeSourceUrl(page.source_url), title: page.title, text: page.text };
  if (!options.safety_gate || !options.llm) {
    return review("规则解析不完整；A-03/A-04 安全门或 MG1 LLM adapter 未接入");
  }
  let approved = false;
  const gateStarted = nowIso();
  try {
    approved = await options.safety_gate(input);
  } catch {
    await record("extract.safety_gate", "a03-a04-gate.v1", "failed", [pageRef], [], { started_at: gateStarted, error: "safety gate failed closed" });
    return review("安全门发生错误；按 fail-closed 转人工复核");
  }
  await record(
    "extract.safety_gate",
    "a03-a04-gate.v1",
    approved ? "success" : "rejected",
    [pageRef],
    [{ kind: "SafetyGateDecision", id: pageUrl, sha256: sha256Json({ approved }), url: pageUrl }],
    { started_at: gateStarted, execution: { component_version: "a03-a04-gate.v1" }, decision: { reason: approved ? "approved" : "untrusted page denied", review_required: !approved } },
  );
  if (!approved) return review("A-03/A-04 安全门拒绝将不可信页面送入 LLM");

  const llmStarted = nowIso();
  let draft: unknown;
  try {
    draft = await options.llm(input);
  } catch {
    await record("extract.llm", "mg1-extraction.v1", "failed", [pageRef], [], { started_at: llmStarted, execution: options.llm_execution ?? { component_version: "mg1-extraction.v1" }, error: "LLM request failed; raw output not retained" });
    return review("LLM 请求失败；按 fail-closed 转人工复核");
  }
  let draftHash: string | undefined;
  try { draftHash = sha256Json(draft); } catch { draftHash = undefined; }
  await record(
    "extract.llm",
    "mg1-extraction.v1",
    "success",
    [pageRef],
    draftHash ? [{ kind: "LlmDraft", id: pageUrl, sha256: draftHash, url: pageUrl }] : [],
    { started_at: llmStarted, execution: options.llm_execution ?? { component_version: "mg1-extraction.v1" } },
  );
  const candidate = validateLlmDraft(draft, page, options.min_llm_confidence ?? 0.85);
  const candidateHash = candidate ? sha256Json(candidate) : undefined;
  await record(
    "extract.validate",
    "evidence-quote-validator.v1",
    candidate ? "success" : "review",
    draftHash ? [{ kind: "LlmDraft", id: pageUrl, sha256: draftHash, url: pageUrl }] : [pageRef],
    candidateHash ? [{ kind: "AdvisoryCandidate", id: pageUrl, sha256: candidateHash, url: pageUrl }] : [],
    { execution: { component_version: "evidence-quote-validator.v1" }, ...(candidate ? {} : { decision: { reason: "fields, confidence or source quotes failed validation", review_required: true } }) },
  );
  if (!candidate) return review("LLM 输出未通过字段、置信度或原文证据校验");
  return { status: "candidate", extracted_by: "llm", candidate, next_step: "DQ1", trace_id: traceId, lineage_ids: [...lineageIds] };
}
