/**
 * A-03 数据隔离闸门（第二道防线：出网前的私域标记扫描）。
 *
 * 第一道防线是 MG1 的 data_domain × trust_boundary 检查（调用方主动声明数据域）；
 * 本模块是**兜底的机械闸门**：即使调用方漏传 data_domain=private，只要出网载荷里
 * 出现私域标记（资产号/内网主机名/租户号等），也必须硬拒，不得静默出网。
 *
 * 纪律：
 *  - fail-closed：命中即拒绝，不做"疑似放行"；
 *  - 不回显命中内容：错误与 lineage 只记录「标记名 + 路径」，禁止复制正文（与 P-10 lineage 口径一致）；
 *  - 错误类型可判别（IsolationError 家族），上层据类型终止降级链，不得改投下一家 provider。
 */

/** 私域标记清单（大小写不敏感，子串匹配）。新增标记须同步 CHANGELOG 与 isolation 测试。 */
export const PRIVATE_MARKERS: readonly string[] = [
  "asset_id",
  "internal_host",
  "tenant_id",
  "tenant:",
  "employee_id",
  "-----begin",
  "corp.internal",
  "intranet",
];

export interface ScopeViolation {
  marker: string;
  path: string;
}

/** 隔离类错误基类：调用方据此把失败判为"策略拒绝"而非"provider 故障"。 */
export class IsolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IsolationError";
  }
}

/** 出网载荷命中私域标记。只带标记与路径，不带命中内容。 */
export class ScopeViolationError extends IsolationError {
  readonly violations: ScopeViolation[];
  constructor(violations: ScopeViolation[], context: string) {
    const detail = violations.map((v) => v.marker + "@" + v.path).join(", ");
    super(context + " 含私域标记，已拒绝出网（只报标记与路径，不回显内容）：" + detail);
    this.name = "ScopeViolationError";
    this.violations = violations;
  }
}

const MAX_DEPTH = 8;

/** 深度优先扫描字符串载荷；只返回标记与路径，不返回命中文本。 */
export function scanPrivateMarkers(value: unknown, path = "$"): ScopeViolation[] {
  const hits: ScopeViolation[] = [];
  const walk = (node: unknown, at: string, depth: number): void => {
    if (depth > MAX_DEPTH) return;
    if (typeof node === "string") {
      const lower = node.toLowerCase();
      for (const marker of PRIVATE_MARKERS) {
        if (lower.includes(marker)) hits.push({ marker, path: at });
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, at + "[" + index + "]", depth + 1));
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, item] of Object.entries(node as Record<string, unknown>)) {
        // 键名本身也可能是私域字段（例如 { asset_id: "..." }）
        const lowerKey = key.toLowerCase();
        for (const marker of PRIVATE_MARKERS) {
          if (lowerKey.includes(marker.replace(/:$/, ""))) hits.push({ marker, path: at + "." + key + "（键名）" });
        }
        walk(item, at + "." + key, depth + 1);
      }
    }
  };
  walk(value, path, 0);
  return hits;
}

/** 出网前调用：命中私域标记即抛 ScopeViolationError（禁静默放行）。 */
export function assertPublicScope(payload: unknown, context: string): void {
  const violations = scanPrivateMarkers(payload);
  if (violations.length > 0) throw new ScopeViolationError(violations, context);
}
