/**
 * MG1 ModelProfile（contracts/models.yml 的 TS 镜像）。
 * 纪律：业务代码只认 role 名；切 provider 只改 yml + .env，代码零改动。
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export type ProviderType = "cache" | "openai_compat";
export type RoleName = "planner" | "answerer" | "embedder" | "reranker" | "decision";

export interface ModelProfile {
  role: RoleName;
  provider: string;
  model_id: string;
  model_version: string;
  max_rpm: number;
  max_tpm: number;
  max_concurrency: number;
  timeout_ms: number;
  fallback_chain: string[];
  /**
   * 降级到真实 provider 时该用的模型名（provider → model_id）。
   * 不配则沿用 "<provider>-fallback" 这个名字，而它在真实 provider 上必然不存在
   * （HTTP 400/404），所以跨真实 provider 的降级必须在此显式声明，否则等于降级不通。
   * cache provider 不需要配：它不校验模型名。
   */
  fallback_model_ids?: Record<string, string>;
  /** C-05：该角色默认数据域；缺省 public。调用方可在请求里显式指定。 */
  data_domain?: DataDomain;
  capability_flags: Record<string, unknown>;
}

/** C-05：provider 信任边界。cloud=外部云 API；local=本机自建；cache=确定性占位。 */
export type TrustBoundary = "cloud" | "local" | "cache";

/** C-05：数据域。private 数据禁止流入 cloud provider（A-03 硬拒）。 */
export type DataDomain = "public" | "private";

export interface ProviderDef {
  type: ProviderType;
  base_url_env?: string;
  base_url_default?: string;
  api_key_env?: string;
  capability_flags?: Record<string, unknown>;
  /** C-05：缺省按 type 推断（openai_compat→cloud，cache→cache）；显式声明优先。 */
  trust_boundary?: TrustBoundary;
}

export interface ModelsConfig {
  version: number;
  providers: Record<string, ProviderDef>;
  default_fallback_chain: string[];
  roles: Record<RoleName, ModelProfile>;
}

/** 解析 models.yml（无 YAML 库，按本项目配置子集手写解析，零依赖）。 */
export function loadModelsConfig(path = resolve(process.env.MODELS_CONFIG_PATH ?? "config/models.yml")): ModelsConfig {
  const text = readFileSync(path, "utf8");
  // 顶层 sections
  const sections = splitSections(text);
  const version = Number(text.match(/^version:\s*(\d+)/m)?.[1] ?? 1);

  // default_fallback_chain: [a, b, c]
  const chainLine = text.match(/^default_fallback_chain:\s*\[([^\]]*)\]/m);
  const default_fallback_chain = chainLine
    ? chainLine[1]!.split(",").map((s) => s.trim()).filter(Boolean)
    : ["cache", "template"];

  // providers 段：缩进两格的 provider 名 -> fields
  const providers: Record<string, ProviderDef> = {};
  const provBlock = sections.get("providers") ?? "";
  for (const m of provBlock.matchAll(/^  ([a-z_]+):.*\n((?:    .*\n?)*)/gm)) {
    const name = m[1]!;
    const body = m[2]!;
    const type = body.match(/type:\s*(\w+)/)?.[1] ?? "cache";
    providers[name] = {
      type: type as ProviderType,
      base_url_env: body.match(/base_url_env:\s*(\S+)/)?.[1],
      base_url_default: body.match(/base_url_default:\s*(\S+)/)?.[1],
      api_key_env: body.match(/api_key_env:\s*(\S+)/)?.[1],
      capability_flags: parseInlineFlags(body),
      trust_boundary: parseTrustBoundary(body, type as ProviderType),
    };
  }

  // roles 段
  const roles = {} as Record<RoleName, ModelProfile>;
  const rolesBlock = sections.get("roles") ?? "";
  for (const m of rolesBlock.matchAll(/^  ([a-z_]+):.*\n((?:    .*\n?)*)/gm)) {
    const role = m[1] as RoleName;
    const body = m[2]!;
    roles[role] = {
      role,
      provider: body.match(/provider:\s*(\S+)/)?.[1] ?? "cache",
      model_id: body.match(/model_id:\s*(\S+)/)?.[1] ?? "unknown",
      model_version: body.match(/model_version:\s*(\S+)/)?.[1] ?? "v0",
      max_rpm: Number(body.match(/max_rpm:\s*(\d+)/)?.[1] ?? 600),
      max_tpm: Number(body.match(/max_tpm:\s*(\d+)/)?.[1] ?? 2000000),
      max_concurrency: Number(body.match(/max_concurrency:\s*(\d+)/)?.[1] ?? 4),
      timeout_ms: Number(body.match(/timeout_ms:\s*(\d+)/)?.[1] ?? 30000),
      fallback_chain: parseChain(body) ?? ["cache", "template"],
      fallback_model_ids: parseFallbackModelIds(body),
      capability_flags: parseInlineFlags(body),
      data_domain: parseDataDomain(body),
    };
  }

  return { version, providers, default_fallback_chain, roles };
}

function parseTrustBoundary(body: string, type: ProviderType): TrustBoundary {
  const raw = body.match(/trust_boundary:\s*(\S+)/)?.[1];
  if (raw === "cloud" || raw === "local" || raw === "cache") return raw;
  return type === "cache" ? "cache" : "cloud";
}

function parseDataDomain(body: string): DataDomain {
  return body.match(/data_domain:\s*private/) ? "private" : "public";
}

function parseChain(body: string): string[] | undefined {
  const m = body.match(/fallback_chain:\s*\[([^\]]*)\]/);
  return m ? m[1]!.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
}

/**
 * fallback_model_ids: { tokendance: qwen3.7-text-embedding, deepseek: deepseek-embed }
 * 单行花括号映射，键值都不含空格。缺省返回 undefined（调用方用 provider+"-fallback"）。
 */
function parseFallbackModelIds(body: string): Record<string, string> | undefined {
  const m = body.match(/fallback_model_ids:\s*\{([^}]*)\}/);
  if (!m) return undefined;
  const out: Record<string, string> = {};
  for (const pair of m[1]!.split(",")) {
    const [k, v] = pair.split(":").map((s) => s?.trim() ?? "");
    if (k && v) out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function parseInlineFlags(body: string): Record<string, unknown> {
  const m = body.match(/capability_flags:\s*\{([^}]*)\}/);
  if (!m) return {};
  const out: Record<string, unknown> = {};
  for (const pair of m[1]!.split(",")) {
    const [k, v] = pair.split(":").map((s) => s?.trim() ?? "");
    if (!k) continue;
    out[k] = v === "true" ? true : v === "false" ? false : v && /^\d+$/.test(v) ? Number(v) : v;
  }
  return out;
}

function splitSections(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  const buf: string[] = [];
  for (const line of text.split("\n")) {
    const h = line.match(/^([a-z_]+):\s*$/);
    if (h) {
      if (current) out.set(current, buf.join("\n"));
      current = h[1]!;
      buf.length = 0;
    } else if (current && (line.startsWith("  ") || line.trim() === "")) {
      buf.push(line);
    } else if (current && !line.startsWith(" ")) {
      out.set(current, buf.join("\n"));
      current = null;
    }
  }
  if (current) out.set(current, buf.join("\n"));
  return out;
}
