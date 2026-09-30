/**
 * openai_compat provider：所有 OpenAI 兼容端点共用一份实现。
 * 红线落地：只用全局 fetch，禁止 import 任何 provider SDK。
 * 支持 /chat/completions 与 /embeddings；rerank 非标准端点——
 * provider capability_flags.rerank=false 时上层必须显式报错，禁止静默降级成 chat。
 */
import type { ChatMessage, ChatParams, ProviderResult } from "../types.js";
import { assertPublicScope } from "../isolation.js";
import type { TrustBoundary } from "../profiles.js";

export interface OpenAiCompatConfig {
  baseUrl: string;
  apiKey: string;
  modelId: string;
  timeoutMs: number;
  rerankCapable: boolean;
  /**
   * A-03：该 provider 的信任边界。非 local（含缺省）时出网前必须过私域标记扫描——
   * local provider 是私有数据的合法目的地，不扫描。
   */
  trustBoundary?: TrustBoundary;
}

export class OpenAiCompatError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "OpenAiCompatError";
    this.status = status;
  }
}

export function resolveConfig(
  def: {
    base_url_env?: string;
    base_url_default?: string;
    api_key_env?: string;
    trust_boundary?: TrustBoundary;
    capability_flags?: Record<string, unknown>;
  },
  modelId: string,
  timeoutMs: number,
): OpenAiCompatConfig {
  return {
    baseUrl: envOr(def.base_url_env, def.base_url_default ?? ""),
    apiKey: envOr(def.api_key_env, "EMPTY"),
    modelId,
    timeoutMs,
    rerankCapable: def.capability_flags?.rerank !== false,
    trustBoundary: def.trust_boundary ?? "cloud",
  };
}

function envOr(name: string | undefined, fallback: string): string {
  return (name && process.env[name]) || fallback;
}

async function postJson(url: string, body: unknown, cfg: OpenAiCompatConfig): Promise<any> {
  // A-03 第二道隔离闸门：唯一出网点。非 local 边界（缺省按 cloud，fail-closed）时，
  // 即使调用方漏传 data_domain，含私域标记的载荷也不得出网；local 是私有数据合法目的地，不扫描。
  if ((cfg.trustBoundary ?? "cloud") !== "local") assertPublicScope(body, "openai_compat 请求体");
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + cfg.apiKey,
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new OpenAiCompatError("HTTP " + res.status + ": " + text.slice(0, 200), res.status);
    }
    return (await res.json()) as any;
  } finally {
    clearTimeout(timer);
  }
}

export async function compatChat(
  cfg: OpenAiCompatConfig,
  messages: ChatMessage[],
  params: ChatParams = {},
): Promise<ProviderResult> {
  const json = await postJson(cfg.baseUrl.replace(/\/$/, "") + "/chat/completions", {
    model: cfg.modelId,
    messages,
    temperature: params.temperature ?? 0.2,
    max_tokens: params.max_tokens,
  }, cfg);
  const choice = json?.choices?.[0]?.message?.content ?? "";
  if (!choice) throw new OpenAiCompatError("provider 返回空 choices");
  return {
    text: choice,
    usage: {
      prompt_tokens: Number(json?.usage?.prompt_tokens ?? 0),
      completion_tokens: Number(json?.usage?.completion_tokens ?? 0),
    },
  };
}

export async function compatEmbed(cfg: OpenAiCompatConfig, texts: string[]): Promise<number[][]> {
  const json = await postJson(cfg.baseUrl.replace(/\/$/, "") + "/embeddings", {
    model: cfg.modelId,
    input: texts,
  }, cfg);
  const data = json?.data;
  if (!Array.isArray(data) || data.length !== texts.length) {
    throw new OpenAiCompatError("provider embeddings 返回数量与输入不符");
  }
  const ordered: Array<number[] | undefined> = Array.from({ length: texts.length });
  for (const [position, row] of data.entries()) {
    const index = Number.isInteger(row?.index) ? Number(row.index) : position;
    if (index < 0 || index >= texts.length || ordered[index] !== undefined) {
      throw new OpenAiCompatError("provider embeddings index 无效或重复");
    }
    const vector = row?.embedding;
    if (!Array.isArray(vector) || vector.length === 0 || vector.some((value: unknown) => typeof value !== "number" || !Number.isFinite(value))) {
      throw new OpenAiCompatError("provider embeddings 向量为空或包含非数值");
    }
    ordered[index] = vector as number[];
  }
  if (ordered.some((vector) => vector === undefined)) throw new OpenAiCompatError("provider embeddings 缺少输入项");
  return ordered.map((vector) => vector!);
}

/** rerank 无标准 OpenAI 兼容端点：能力缺失必须显式报错。 */
export function compatRerankUnsupported(providerName: string): never {
  throw new OpenAiCompatError(
    "provider " + providerName + " 无 rerank 能力（capability_flags.rerank=false），禁止静默降级",
  );
}
