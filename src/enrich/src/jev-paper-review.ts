/**
 * F1 论文评审的本地 Jev 端口（Open-Jev 开源复现；代码 MIT / 权重 Apache-2.0）。
 *
 * 定位：替换 F1 的词重合启发式在"二审"环节的盲区——2026-10-09 探针实测，
 * 锚点词+机制词共现会把催化/物理论文判成漏洞相关（48% 假阳性）。Choice 原语
 * 直接对 (漏洞报告, 候选论文) 做语义判定并返回类型化概率，天然支持弃权。
 *
 * 纪律（与项目红线、Jev 调研五铁律一致）：
 *   1. 独立弃权出口：related / unrelated / uncertain 三路；不确定不等于不相关；
 *   2. 阈值 >= 0.9 才自动执行（可配，但不得低于 0.8——index.ts 对 suggested 的
 *      confidence 下限是 0.8，低于它只会被上游判弃权，不如在端口内就说清楚）；
 *   3. 本端口只产 advisory sidecar：不改 PaperLink 分数/顺序，不改 published
 *      EnrichmentResult（与 StepFun 评审同口径，由 index.ts 的 f1 advisory 分支落库）；
 *   4. 服务不可达/响应畸形一律抛错，由上游转 degraded lineage + FallbackEvent，
 *      规则结果原样保留——禁止静默兜底（不能把"模型没说话"当成"模型说不行"）；
 *   5. 模型标识必须钉版本（官方别名会静默漂移），落 lineage 前不得省略。
 *
 * 已知限制：本实现及 Open-Jev 在该任务上的准确率/校准误差尚未实测；不得把
 * 其他 Jev 实现的历史数字当作此模型指标。概率不等于正确率，英语输入也不保证
 * 判定可靠。A/B 结论出来前不得把建议当事实。
 */
import { screenPromptInjection } from "@safetrace/shared";
import { requestJevChoice } from "./jev-decision-client.js";
import type { PaperReviewPort, PaperReviewOutcome, PaperReviewRequest } from "./stepfun-paper-review.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:8791";
/** index.ts 对 suggested 的 confidence 下限；端口阈值低于它没有意义。 */
const CONFIDENCE_FLOOR = 0.8;
/** 原调研铁律：>=0.9 才自动执行。 */
const DEFAULT_THRESHOLD = 0.9;
const MAX_QUERY_CHARS = 512;
const MAX_TITLE_CHARS = 600;
const MAX_SUMMARY_CHARS = 1000;
const MAX_PAPERS = 5;
const RELATED = "related", UNRELATED = "unrelated", UNCERTAIN = "uncertain";

export interface JevPaperReviewerOptions {
  /** Open-Jev 服务基地址；缺省读 env JEV_BASE_URL，再缺省 http://127.0.0.1:8791。 */
  baseUrl?: string;
  /** 钉死的模型标识（落 lineage）。必须显式给版本，禁止使用会漂移的别名。 */
  modelId: string;
  /** 保留阈值：P(related) >= threshold 才进 suggested。默认 0.9。 */
  threshold?: number;
  /** 单次请求超时毫秒，默认 20000。 */
  timeoutMs?: number;
  /** 测试注入用；缺省全局 fetch。 */
  fetchImpl?: typeof fetch;
}

function resolveBaseUrl(options: JevPaperReviewerOptions): string {
  const fromEnv = process.env.JEV_BASE_URL;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv.trim().replace(/\/+$/, "");
  return (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
}

/** 请求体：共享 state + 一个 Choice 问题（related/unrelated 显式互斥出口）。 */
export function buildJevRequest(request: PaperReviewRequest, paper: { paper_id: string; title: string }, summary: string | undefined): { state: string; questions: Record<string, unknown> } {
  const lines = ["Vulnerability report:", request.query.trim(), "", "Candidate paper:", "Title: " + paper.title.trim()];
  if (summary && summary.trim()) lines.push("Summary: " + summary.trim().slice(0, MAX_SUMMARY_CHARS));
  return {
    state: lines.join("\n"),
    questions: {
      relevance: {
        type: "choice",
        instructions: "Does the candidate paper analyze this specific vulnerability (the same product and the same weakness)? Pick the single best answer.",
        criteria: {
          [RELATED]: "The paper analyzes, exploits, mitigates or reports this specific product or vulnerability, or explicitly cites its CVE identifier.",
          [UNRELATED]: "The paper only shares common words with the report, studies a different product with a similar name, or is about an unrelated topic.",
          [UNCERTAIN]: "There is insufficient evidence in the supplied title and abstract to establish or rule out this specific vulnerability relationship; abstain rather than guess.",
        },
      },
    },
  };
}

export { parseJevChoiceAnswer } from "./jev-decision-client.js";

export function createJevPaperReviewer(options: JevPaperReviewerOptions): PaperReviewPort {
  if (!options.modelId || options.modelId.trim() === "") throw new Error("createJevPaperReviewer: modelId 必须钉版本（官方别名会静默漂移）");
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  if (!Number.isFinite(threshold) || threshold < CONFIDENCE_FLOOR || threshold > 1) throw new Error("createJevPaperReviewer: threshold 必须为 " + CONFIDENCE_FLOOR + "–1 的数字（低于 " + CONFIDENCE_FLOOR + " 会被上游 confidence 校验判弃权，没有意义）");
  const baseUrl = resolveBaseUrl(options);
  const endpoint = new URL(baseUrl);
  if (endpoint.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/") throw new Error("Open-Jev endpoint must be a credential-free loopback HTTP origin");
  const timeoutMs = options.timeoutMs ?? 20_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error("Open-Jev timeoutMs must be a positive integer");
  const fetcher = options.fetchImpl ?? fetch;

  return async (request: PaperReviewRequest): Promise<PaperReviewOutcome> => {
    const abstain = (reason: string, flags?: string[]): PaperReviewOutcome => ({ status: "abstained", reason, ...(flags ? { flags } : {}), model_id: options.modelId, provider: "openjev" });
    // 准入校验（与 StepFun 评审同口径）：候选数、查询长度、URL/控制字符、id 唯一性
    if (request.papers.length < 1 || request.papers.length > MAX_PAPERS) return abstain("candidate count is not eligible for local review");
    if (request.query.length > MAX_QUERY_CHARS || /(?:https?|file):\/\//i.test(request.query)) return abstain("query is oversized or contains a URL");
    const ids = request.papers.map(p => p.paper_id);
    if (new Set(ids).size !== ids.length) return abstain("candidate paper ids are duplicated");
    const summaries = request.paper_summaries ?? {};
    for (const paper of request.papers) {
      if (typeof paper.paper_id !== "string" || paper.paper_id.length === 0 || paper.paper_id.length > 128 || /[\r\n]|(?:https?|file):\/\//i.test(paper.paper_id)) return abstain("candidate paper id is malformed or oversized");
      if (typeof paper.title !== "string" || paper.title.trim().length === 0 || paper.title.length > MAX_TITLE_CHARS || /[\r\n]|(?:https?|file):\/\//i.test(paper.title)) return abstain("candidate paper title is malformed or oversized");
      const summary = summaries[paper.paper_id];
      if (summary !== undefined && (typeof summary !== "string" || summary.length > MAX_SUMMARY_CHARS * 4)) return abstain("candidate paper summary is malformed or oversized");
    }
    // A-04 注入筛查：论文标题/摘要是外部内容，进模型前先过闸门
    const screen = screenPromptInjection([request.query, ...request.papers.map(p => p.title), ...Object.values(summaries)]);
    if (!screen.screened || !screen.allowed) return abstain("A-04 heuristic screen blocked F1 metadata", screen.flags);

    const kept: string[] = [];
    const probabilities: Record<string, number> = {};
    for (const paper of request.papers) {
      // 显式失败：上游会转 degraded lineage + FallbackEvent，规则结果原样保留
      const decision = await requestJevChoice(buildJevRequest(request, paper, summaries[paper.paper_id]), {
        baseUrl, modelId: options.modelId, timeoutMs, fetchImpl: fetcher,
      }).catch((error: unknown) => { throw new Error("Open-Jev review request failed for " + paper.paper_id + ": " + (error instanceof Error ? error.message : String(error))); });
      probabilities[paper.paper_id] = decision.answer.probabilities.related ?? 0;
      if ((decision.answer.probabilities.related ?? 0) >= threshold) kept.push(paper.paper_id);
    }
    if (kept.length === 0) return abstain("no candidate reached the local relevance threshold " + threshold);
    // confidence 取保留集合的最小概率（保守）：上游要求 >=0.8，阈值下限已保证
    const confidence = Math.min(...kept.map(id => probabilities[id]!));
    return { status: "suggested", paper_ids: kept, confidence, model_id: options.modelId, provider: "openjev", probabilities };
  };
}
