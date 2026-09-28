/**
 * cache provider：确定性输出，零外网依赖。
 * - chat：按输入哈希取稳定模板答案（同输入同输出，可复现）
 * - embed：hash 向量（dim 由 capability_flags 声明，默认 256）
 * - rerank：按词项重合度的确定性打分（绝不冒充模型精排）
 * 用途：断网演示、单测、L3 降级链终点。所有输出可由 provider 名辨识。
 */
import type { ChatMessage, ProviderResult } from "../types.js";

/** FNV-1a 稳定哈希 → 可复现伪随机。 */
export function hash32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** 确定性单位向量（dim 维）。同输入恒等，供离线检索冒烟。 */
export function hashEmbedding(text: string, dim = 256): number[] {
  const v = new Array<number>(dim).fill(0);
  const tokens = tokenize(text);
  for (const tok of tokens) {
    const h = hash32(tok);
    v[h % dim] = (v[h % dim] ?? 0) + 1;
    v[(h >>> 8) % dim] = (v[(h >>> 8) % dim] ?? 0) + 0.5;
  }
  if (tokens.length === 0) v[0] = 1;
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1;
  return v.map((x) => x / norm);
}

/** 确定性 rerank：查询词在文档中的 TF 归一。 */
export function hashRerank(query: string, docs: string[]): Array<{ index: number; score: number }> {
  const qTokens = new Set(tokenize(query));
  return docs
    .map((doc, index) => {
      const dTokens = tokenize(doc);
      const hits = dTokens.filter((t) => qTokens.has(t)).length;
      const score = dTokens.length === 0 ? 0 : hits / Math.sqrt(dTokens.length);
      return { index, score };
    })
    .sort((a, b) => b.score - a.score);
}

export function cacheChat(messages: ChatMessage[], modelId: string): ProviderResult {
  const lastUser = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";
  const h = hash32(lastUser);
  const tokenCount = tokenize(lastUser).length;
  const lines = [
    `[cache provider · ${modelId}] 离线确定性应答（#${h.toString(16)}）。`,
    "结论：当前为降级通道，未调用真实模型；此为基于输入结构的占位回答。",
    "证据：无（本回答不引用任何情报条目）。",
    "推理链：输入长度 " + lastUser.length + " 字符；命中词项 " + tokenCount + " 个。",
    "置信度：0.1（低置信，需接入真实 provider）。",
  ];
  const text = lines.join("\n");
  return {
    text,
    usage: {
      prompt_tokens: approxTokens(messages.map((m) => m.content).join(" ")),
      completion_tokens: approxTokens(text),
    },
  };
}

export function approxTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 2));
}

/** 中英文混合粗分词：英文/数字整词 + 中文单字。 */
export function tokenize(text: string): string[] {
  return text.toLowerCase().match(/[a-z0-9_]+|[\u4e00-\u9fa5]/g) ?? [];
}
