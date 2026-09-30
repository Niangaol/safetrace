/** MG1 对外类型（contracts/openapi.yaml 的 TS 镜像）。 */
export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatParams {
  temperature?: number;
  max_tokens?: number;
}

export interface LlmReply {
  text: string;
  model_id: string;
  provider: string;
  usage: { prompt_tokens: number; completion_tokens: number };
  latency_ms: number;
  cached: boolean;
  degraded_to: string;
}

export interface Embedding {
  vectors: number[][];
  model_id: string;
  model_version?: string;
  provider: string;
  latency_ms: number;
  cached: boolean;
  degraded_to: string;
}

export interface RankedDoc {
  index: number;
  score: number;
}

export interface RankedDocs {
  ranked: RankedDoc[];
  model_id: string;
  provider: string;
  latency_ms: number;
  cached: boolean;
  degraded_to: string;
}

/** provider 单次调用的原始结果（未含路由元数据）。 */
export interface ProviderResult {
  text: string;
  usage: { prompt_tokens: number; completion_tokens: number };
}

export interface UsageRecord {
  ts: string;
  role: string;
  provider: string;
  model_id: string;
  call: "chat" | "embed" | "rerank";
  prompt_tokens: number;
  completion_tokens: number;
  latency_ms: number;
  cached: boolean;
  degraded_to: string;
  trace_id: string;
}
