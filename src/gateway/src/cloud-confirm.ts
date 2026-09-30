/** 传给人工关卡的上下文：让人知道"为什么要出网、出到哪、用什么模型"。 */
export interface CloudFallbackRequest {
  role: RoleName;
  /** 失败的上一跳 provider（本地通道） */
  fromProvider: string;
  fromError: string;
  /** 将要出网的 provider / 模型 */
  toProvider: string;
  toModelId: string;
  /** 该 provider 的信任边界，固定为 cloud */
  trustBoundary: "cloud";
  /** 调用类型 */
  call: "chat" | "embed" | "rerank";
  traceId: string;
}

/**
 * 云端降级的人工关卡（CLI 交互版）。
 *
 * 背景：本地模型缺失/不可用时，MG1 会按 fallback_chain 降级。降到 cloud provider
 * 会出网、可能计费，用户明确要求"必须人工点头，拒绝就算了"。
 *
 * 行为：
 *   - 交互式 TTY：把「为什么降级 / 出网到哪 / 用什么模型」讲清楚，等 y/n；
 *     30 秒不答按拒绝处理（宁可漏一次，绝不未经同意出网）。
 *   - 非交互（无 TTY，如 CI、服务长跑、管道）：直接拒绝并说明原因。
 *   - 环境变量安全阀：SAFETRACE_CLOUD_FALLBACK=never 时连问都不问，一律拒绝
 *     （默认就是这个值，要显式改成 ask/always 才会放开）。
 *
 * 用法：
 *   const gw = new ModelGateway({ bus, confirmCloudFallback: createCliCloudConfirm() });
 */
import { createInterface } from "node:readline";
import type { RoleName } from "./profiles.js";

/** never=直接拒绝（默认，fail closed）；ask=交互询问；always=不再询问直接放行。 */
export type CloudFallbackPolicy = "never" | "ask" | "always";

export function cloudFallbackPolicy(): CloudFallbackPolicy {
  const raw = (process.env.SAFETRACE_CLOUD_FALLBACK ?? "never").trim().toLowerCase();
  return raw === "ask" || raw === "always" ? raw : "never";
}

const PROMPT_TIMEOUT_MS = 30_000;

function describe(req: CloudFallbackRequest): string {
  return [
    "",
    "┌─────────────────────────────────────────────────────────────",
    "│ ⚠️  即将调用云端模型（会出网、可能计费）",
    "├─────────────────────────────────────────────────────────────",
    "│ 触发角色   : " + req.role + " (" + req.call + ")",
    "│ 本地通道   : " + req.fromProvider + " 不可用 → " + req.fromError.slice(0, 120),
    "│ 将出网到   : " + req.toProvider + "  模型 " + req.toModelId,
    "│ 信任边界   : " + req.trustBoundary,
    "│ trace_id   : " + req.traceId,
    "└─────────────────────────────────────────────────────────────",
    "输入 y 放行本次调用，其它任何输入（含直接回车）都视为拒绝：",
  ].join("\n");
}

/**
 * 生成 confirmCloudFallback 回调。
 * 返回值语义与 MG1 约定一致：true=放行，false=拒绝。
 */
export function createCliCloudConfirm(): (req: CloudFallbackRequest) => Promise<boolean> {
  return async (req: CloudFallbackRequest): Promise<boolean> => {
    const policy = cloudFallbackPolicy();
    if (policy === "never") {
      console.error("[cloud-gate] SAFETRACE_CLOUD_FALLBACK=never（默认）：已拒绝降级到云端 " + req.toProvider + "，未出网");
      return false;
    }
    if (policy === "always") {
      console.error("[cloud-gate] SAFETRACE_CLOUD_FALLBACK=always：允许降级到云端 " + req.toProvider + "（" + req.toModelId + "）");
      return true;
    }
    // policy === "ask"
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      console.error("[cloud-gate] 非交互环境（无 TTY），无法取得人工意见 → 拒绝降级到云端 " + req.toProvider + "，未出网");
      return false;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    try {
      const answer = await new Promise<string>((resolve) => {
        const timer = setTimeout(() => resolve("__timeout__"), PROMPT_TIMEOUT_MS);
        rl.question(describe(req), (a) => {
          clearTimeout(timer);
          resolve(String(a ?? "").trim().toLowerCase());
        });
      });
      if (answer === "__timeout__") {
        console.error("[cloud-gate] 30 秒未应答，按拒绝处理（未出网）");
        return false;
      }
      const ok = answer === "y" || answer === "yes";
      console.error(ok ? "[cloud-gate] 人工已同意，继续调用云端 " + req.toProvider : "[cloud-gate] 人工已拒绝，不出网");
      return ok;
    } finally {
      rl.close();
    }
  };
}
