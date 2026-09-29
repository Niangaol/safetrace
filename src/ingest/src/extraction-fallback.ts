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
  | { status: "candidate"; extracted_by: "rules" | "llm"; candidate: AdvisoryCandidate; next_step: "DQ1" }
  | { status: "needs_human_review"; reason: string; rule_candidate?: AdvisoryCandidate };

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;
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
    source_url: page.source_url,
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
  return { source_url: page.source_url, title, summary, cve_ids: cveIds, confidence, evidence_quotes: evidenceQuotes };
}

/**
 * 确定性规则优先；只有调用方同时提供安全门和 MG1 adapter 且门返回 true 才调用 LLM。
 * 本函数不连接云模型，也不发布 IntelItem；未确定内容只返回 needs_human_review。
 */
export async function extractAdvisoryWithFallback(
  page: PageFetchResult,
  options: { safety_gate?: UntrustedTextGate; llm?: LlmExtractionPort; min_llm_confidence?: number } = {},
): Promise<ExtractionResult> {
  const deterministic = rulesCandidate(page);
  if (deterministic) return { status: "candidate", extracted_by: "rules", candidate: deterministic, next_step: "DQ1" };
  const input: LlmExtractionInput = { source_url: page.source_url, title: page.title, text: page.text };
  if (!options.safety_gate || !options.llm) {
    return { status: "needs_human_review", reason: "规则解析不完整；A-03/A-04 安全门或 MG1 LLM adapter 未接入" };
  }
  try {
    if (!(await options.safety_gate(input))) return { status: "needs_human_review", reason: "A-03/A-04 安全门拒绝将不可信页面送入 LLM" };
  } catch {
    return { status: "needs_human_review", reason: "安全门发生错误；按 fail-closed 转人工复核" };
  }
  try {
    const draft = await options.llm(input);
    const candidate = validateLlmDraft(draft, page, options.min_llm_confidence ?? 0.85);
    if (!candidate) return { status: "needs_human_review", reason: "LLM 输出未通过字段、置信度或原文证据校验" };
    return { status: "candidate", extracted_by: "llm", candidate, next_step: "DQ1" };
  } catch {
    return { status: "needs_human_review", reason: "LLM 请求失败；按 fail-closed 转人工复核" };
  }
}
