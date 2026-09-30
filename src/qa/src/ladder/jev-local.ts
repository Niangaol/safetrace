/**
 * Jev 本地复现（DecisionProvider 的零成本本地退路 / A-B 对照）。
 *
 * 背景：官方 Jev 权重闭源；2026-09 起出现可本地跑的开源复现（APUS 的 MIT 实现、
 * yzfly/edgejev 的 ONNX+INT8 版、mode-io/vllm-jev 的服务化版）。本文件不绑定任何
 * 一个特定复现包，而是用 llama.cpp 的 chat 实例复现其核心机制：
 *
 *   「跳过自回归解码，单 Token Logits 直接打分」
 *
 * 即把候选 choice 逐个打分（prompt + 候选走一次前向，取下一个 token 的 logprob），
 * 选分数最高的候选；低于阈值则返回 null（弃权，让阶梯显式下坠到人工层）。
 *
 * 口径保持不变（原调研五条铁律）：
 *   1. other 出口：候选之外显式 abstain，不硬选；
 *   2. 阈值 >= 0.9 才自动执行（本文件阈值可配，默认照旧）；
 *   3. 阈值按问法逐题校准；
 *   4. 留 state-blind 基线；
 *   5. MC 顺序无偏。
 *
 * 已知限制（必须如实标注，不得隐瞒）：
 *   - 本地复现版的中文精度与校准问题没有解决，历史实测 ECE 约 0.254；
 *   - 因此它只做零成本本地退路与 A/B 对照，**不进中文生产关键链路**；
 *   - 默认不启用（需显式传 options 或设环境变量），避免悄悄改变决策行为。
 */
import type { DecisionReply } from "@safetrace/shared";
import type { LadderContext, LlmResolver } from "./decision-ladder.js";

export interface JevLocalOptions {
  /** llama-server chat 实例，默认 http://127.0.0.1:8080/v1 */
  baseUrl?: string;
  /** 候选列表；缺省从 ctx.state.choices 读 */
  choices?: string[];
  /** 自动执行阈值，默认 0.9（原调研口径）。低于它一律弃权下坠。 */
  threshold?: number;
  /** 超时毫秒，默认 20000 */
  timeoutMs?: number;
  /** 测试注入用 */
  fetchImpl?: typeof fetch;
}

export interface JevScoreRow {
  choice: string;
  /** 该候选的归一化得分（0~1） */
  score: number;
}

export interface JevOutcome {
  scores: JevScoreRow[];
  /** 最高分候选；全部低于阈值时为 undefined（弃权） */
  best: JevScoreRow | undefined;
  abstained: boolean;
}

/** 基地址：env LOCAL_LLM_BASE_URL 优先，其次 options，最后默认值。 */
function resolveBaseUrl(options: JevLocalOptions): string {
  const fromEnv = process.env.LOCAL_LLM_BASE_URL;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv.replace(/\/+$/, "");
  return (options.baseUrl ?? "http://127.0.0.1:8080/v1").replace(/\/+$/, "");
}

/**
 * 候选集打分：把候选编号列出让模型直接选，取它对「选项编号」这一 token 的 logprob。
 *
 * 这正是 Jev 论文口径的"跳过自 autoregressive 解码、单 Token Logits 直接打分"：
 * 不做多轮生成，一次前向拿下一个 token 的分布，从分布里读每个候选编号的概率。
 *
 * 实现要点（踩过的坑，别再改回去）：
 *   - 不能逐候选问"这个候选对吗"：模型对每个候选都会倾向答"是"，
 *     分数全在 0.99 以上、毫无区分度（实测选错过正确答案）。
 *   - 必须让模型在一组互斥编号里选，才能拿到可比较的相对概率。
 *   - top_logprobs 要足够大以覆盖候选编号数，否则候选缺失时按 0 分处理并如实标注。
 */
export async function scoreChoices(prompt: string, choices: string[], options: JevLocalOptions = {}): Promise<JevOutcome> {
  if (choices.length === 0) return { scores: [], best: undefined, abstained: true };
  const fetcher = options.fetchImpl ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? 20000);
  try {
    const list = choices.map((c, i) => (i + 1) + ". " + c).join("\n");
    const content = prompt + "\n\n选项：\n" + list + "\n\n只回答正确选项的编号（1~" + choices.length + "），不要解释。";
    const res = await fetcher(resolveBaseUrl(options) + "/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + (process.env.LOCAL_LLM_API_KEY ?? "EMPTY") },
      body: JSON.stringify({
        model: process.env.LOCAL_LLM_MODEL_ID ?? "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
        messages: [{ role: "user", content }],
        max_tokens: 1,
        temperature: 0,
        logprobs: true,
        top_logprobs: Math.max(choices.length + 2, 8),
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const json = await res.json() as { choices?: Array<{ logprobs?: { content?: Array<{ token?: string; logprob?: number }> } }> };
    const rows = json?.choices?.[0]?.logprobs?.content ?? [];
    // 读每个候选编号的 logprob；编号 token 常写作 "1" / " 1"，trim 后比较
    const rows2: JevScoreRow[] = [];
    for (let i = 0; i < choices.length; i += 1) {
      const token = String(i + 1);
      const hit = rows.find((r) => (r.token ?? "").trim() === token);
      const logprob = hit?.logprob;
      rows2.push({
        choice: choices[i]!,
        // 缺该编号（top_logprobs 没覆盖到）时记 0 分，如实反映"模型没考虑它"
        score: typeof logprob === "number" && Number.isFinite(logprob) ? Math.exp(logprob) : 0,
      });
    }
    rows2.sort((a, b) => b.score - a.score);
    const threshold = options.threshold ?? 0.9;
    const best = rows2[0];
    // 阈值口径照旧调研：>=0.9 才自动执行。注意此处概率是 softmax 前的指数 logprob，
    // 且只覆盖 top_logprobs 窗口，故阈值语义与"校准概率"不同，仅作弃权闸门用。
    const abstained = !best || best.score < threshold;
    return { scores: rows2, best: abstained ? undefined : best, abstained };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 生成阶梯 llm 层 resolver。
 * 返回 null = 低置信度弃权，阶梯会显式下坠到人工层（不伪造决策）。
 */
export function createJevLlmResolver(options: JevLocalOptions = {}): LlmResolver {
  return async (ctx: LadderContext): Promise<DecisionReply["decision"] | null> => {
    const choices = options.choices ?? (Array.isArray(ctx.state.choices) ? (ctx.state.choices as string[]) : []);
    if (choices.length === 0) return null;   // 无候选：弃权，不硬选
    const prompt = typeof ctx.state.prompt === "string" ? ctx.state.prompt : JSON.stringify(ctx.state);
    const outcome = await scoreChoices(prompt, choices, options);
    if (outcome.abstained || !outcome.best) return null;
    return { choice: outcome.best.choice, score: Number(outcome.best.score.toFixed(4)) };
  };
}
