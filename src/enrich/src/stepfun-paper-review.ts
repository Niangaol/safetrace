import { screenPromptInjection } from "@safetrace/shared";
import type { PaperLink } from "@safetrace/shared";

interface ChatMessage { role: "system" | "user"; content: string }
export interface StepFunPaperReviewReply { text: string; provider: string; model_id: string; degraded_to: string }
export interface StepFunPaperReviewClient {
  chat(role: "planner", messages: ChatMessage[], params: { temperature?: number; max_tokens?: number }, traceId: string, dataDomain: "public", contextKey?: string): Promise<StepFunPaperReviewReply>;
}
export interface PaperReviewRequest { trace_id: string; intel_id: string; query: string; papers: PaperLink[]; /** 可选：paper_id -> 摘要（F1 从 arXiv 原始回执带出；StepFun 评审刻意不用，本地 Jev 评审用它做语义判断） */ paper_summaries?: Record<string, string> }
export type PaperReviewOutcome =
  | { status: "suggested"; paper_ids: string[]; confidence: number; model_id: string; provider?: string; probabilities?: Record<string, number> }
  | { status: "abstained"; reason: string; flags?: string[]; model_id?: string; provider?: string };
export type PaperReviewPort = (request: PaperReviewRequest) => Promise<PaperReviewOutcome>;
export interface StepFunPaperReviewOptions { provider: string; modelId: string; apiKeyConfigured: boolean; client: StepFunPaperReviewClient }

function parseJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = text.trim().replace(/^\x60\x60\x60(?:json)?\s*/i, "").replace(/\s*\x60\x60\x60$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const value: unknown = JSON.parse(trimmed.slice(start, end + 1));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}

export function createStepFunPaperReviewer(options: StepFunPaperReviewOptions): PaperReviewPort {
  return async (request) => {
    if (options.provider !== "stepplan" || !options.apiKeyConfigured) return { status: "abstained", reason: "StepPlan planner/key not configured" };
    if (request.papers.length < 2 || request.papers.length > 5 || request.query.length > 512 || /(?:https?|file):\/\//i.test(request.query)) return { status: "abstained", reason: "candidate count or query is not eligible for cloud review" };
    const candidates = request.papers.map((paper) => ({
      paper_id: paper.paper_id,
      title: paper.title,
      ...(paper.year !== undefined ? { year: paper.year } : {}),
      rule_relevance_score: paper.relevance_score,
      evidence_terms: paper.evidence_terms ?? [],
    }));
    const candidateIdList = candidates.map((candidate) => candidate.paper_id);
    const invalidCandidates = candidates.some((candidate) =>
      typeof candidate.paper_id !== "string" || candidate.paper_id.length === 0 || candidate.paper_id.length > 128 || /[\r\n]|(?:https?|file):\/\//i.test(candidate.paper_id)
      || typeof candidate.title !== "string" || candidate.title.trim().length === 0 || candidate.title.length > 600 || /(?:https?|file):\/\//i.test(candidate.title)
      || !Number.isFinite(candidate.rule_relevance_score) || candidate.rule_relevance_score < 0 || candidate.rule_relevance_score > 1
      || !Array.isArray(candidate.evidence_terms) || candidate.evidence_terms.length > 32 || candidate.evidence_terms.some((term) => typeof term !== "string" || term.length > 80 || /(?:https?|file):\/\//i.test(term))
      || (candidate.year !== undefined && (!Number.isSafeInteger(candidate.year) || candidate.year < 1900 || candidate.year > 2100))
    );
    if (invalidCandidates || new Set(candidateIdList).size !== candidateIdList.length) return { status: "abstained", reason: "candidate metadata is malformed, duplicated or oversized" };
    const userPayload = { query: request.query, candidates };
    const screen = screenPromptInjection([JSON.stringify(userPayload)]);
    if (!screen.screened || !screen.allowed) return { status: "abstained", reason: "A-04 heuristic screen blocked F1 metadata", flags: screen.flags };
    const reply = await options.client.chat("planner", [
      { role: "system", content: "你只做论文候选的二次相关性排序。只能返回给定 paper_id 的子集与顺序；不能创建论文、补造事实、改 relevance_score 或声称看过摘要。输入只含公开标题/规则词项，不含摘要全文或 URL。无把握时 abstain=true。confidence 是非校准的模型自评，仅用于是否保留这条人工建议。只输出 JSON：{\"paper_ids\":[\"existing-id\"],\"confidence\":0.9,\"abstain\":false}。此结果只是 review sidecar，不会更改 F1/F4/F6 契约结果。" },
      { role: "user", content: JSON.stringify(userPayload) },
    ], { temperature: 0, max_tokens: 256 }, request.trace_id, "public", "enrich.f1.paper_review");
    if (reply.provider !== "stepplan" || reply.model_id !== options.modelId || reply.degraded_to) throw new Error("StepPlan paper reviewer provider/model mismatch or fallback");
    const body = parseJsonObject(reply.text);
    if (!body || Object.keys(body).some((key) => !["paper_ids", "confidence", "abstain"].includes(key)) || typeof body.abstain !== "boolean") throw new Error("StepPlan paper-review JSON schema rejected");
    if (body.abstain === true) {
      if (Object.keys(body).length !== 1) throw new Error("StepPlan paper-review abstain included extra fields");
      return { status: "abstained", reason: "StepPlan abstained on F1 candidate ordering", model_id: reply.model_id };
    }
    if (Object.keys(body).length !== 3 || !Array.isArray(body.paper_ids) || body.paper_ids.length < 1 || body.paper_ids.length > candidates.length || body.paper_ids.some((id) => typeof id !== "string")) throw new Error("StepPlan paper-review list invalid");
    const ids = body.paper_ids as string[];
    const candidateIds = new Set(candidates.map((candidate) => candidate.paper_id));
    if (new Set(ids).size !== ids.length || ids.some((id) => !candidateIds.has(id))) throw new Error("StepPlan paper-review invented or duplicated paper ids");
    if (typeof body.confidence !== "number" || !Number.isFinite(body.confidence) || body.confidence < 0.8 || body.confidence > 1) return { status: "abstained", reason: "StepPlan paper-review self-confidence below advisory threshold", model_id: reply.model_id };
    return { status: "suggested", paper_ids: ids, confidence: body.confidence, model_id: reply.model_id };
  };
}
