/**
 * P-03：问答侧「某版本是否受影响」确定性入口。
 *
 * 纪律：
 * - 规则与资产线同一实现（@safetrace/assets 的 assessVersionImpact → enrich 版本原语），
 *   不引入第二套比较逻辑；结论与依据由确定性规则产出，
 *   禁止用检索相似度或模型自由生成"是否受影响"；
 * - 只读情报的 entities（product / version_range / cve_ids），零网络、零模型调用；
 * - unknown 不等于安全：无法判定时必须显式说明原因（厂商身份未经本地核实）。
 */
import { normalizeName } from "@safetrace/enrich";
import { assessVersionImpact, nameVariants } from "@safetrace/assets";
import type { VersionImpactVerdict } from "@safetrace/assets";
import type { IntelItem } from "@safetrace/shared";

export interface VersionImpactQuery {
  /** 待判产品名（任意写法；内部归一化后与情报产品标识比对）。 */
  product: string;
  /** 待判具体版本字面量；空串按 unknown 处理（不猜版本）。 */
  version: string;
  /** 限定 CVE（可选）；给出时只在关联该 CVE 的情报里判定。 */
  cve_id?: string;
}

export interface VersionImpactAnswer extends Omit<VersionImpactVerdict, "intel_id"> {
  /** 判定所依据的情报；无任何产品命中时为 null（此时 rule=unavailable）。 */
  intel_id: string | null;
  /** 用户问的版本原样回显（tested_version 可能因缺版本而为空串）。 */
  version: string;
  /** 本次判定关联的 CVE（问者指定优先，否则取依据情报的首个 CVE）。 */
  cve_id: string | null;
  /** 本次实际评估过的情报条数（同产品多源时聚合口径可查）。 */
  candidates: number;
}

/** 产品命中：归一化后的待判产品变体 ∩ 情报产品标识（与 matcher 同口径）。 */
function productMatches(item: IntelItem, asked: ReadonlySet<string>): boolean {
  if (!item.entities.product) return false;
  const advisory = normalizeName(item.entities.product);
  return advisory !== "" && asked.has(advisory);
}

/**
 * 对一批情报回答「product@version 是否受影响」。
 * 聚合口径：任一候选 affected → affected（附依据情报）；否则任一 unknown → 第一个 unknown；
 * 全部 not_affected → 第一个 not_affected。无产品命中 → unknown 并说明原因。
 */
export function answerVersionImpact(items: readonly IntelItem[], query: VersionImpactQuery): VersionImpactAnswer {
  const product = query.product.trim();
  const version = query.version.trim();
  const cve = query.cve_id?.trim().toUpperCase() || null;
  const asked = new Set(nameVariants(product));
  const candidates = items.filter((item) =>
    productMatches(item, asked) && (cve === null || item.cve_ids.some((id) => id.toUpperCase() === cve)),
  );
  if (candidates.length === 0) {
    return {
      intel_id: null, cve_ids: [], product: product || "(未提供)", rule: "unavailable",
      status: "unknown", tested_version: version, matched_ranges: [],
      reason: cve
        ? "未找到产品「" + product + "」与 " + cve + " 的关联情报（无法判定，不等于安全）"
        : "未找到产品「" + product + "」的相关情报（无法判定，不等于安全）",
      vendor_unverified: true, version, cve_id: cve, candidates: 0,
    };
  }
  const verdicts = candidates.map((item) => assessVersionImpact(item, { name: product, version }));
  const chosen = verdicts.find((v) => v.status === "affected")
    ?? verdicts.find((v) => v.status === "unknown")
    ?? verdicts[0]!;
  return {
    ...chosen,
    product: chosen.product || product,
    version,
    cve_id: cve ?? chosen.cve_ids[0] ?? null,
    candidates: candidates.length,
  };
}

/** P-03：版本影响判定的用户可见状态标签（正文渲染用）。 */
export function versionImpactStatusLabel(status: VersionImpactAnswer["status"]): string {
  return status === "affected" ? "受影响" : status === "not_affected" ? "不受影响" : "无法判定";
}