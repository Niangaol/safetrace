/**
 * 组件 × 情报 确定性匹配器。
 *
 * 复用 F2 富化线（f2-assets.ts）导出的同一套版本比较原语：
 * 产品名归一 → 版本解析 → 版本区间判定，不引入第二套比较逻辑。
 *
 * 与 F2 DemoAsset 匹配的差异（本地扫描场景）：
 * - 本地扫描不携带厂商身份 ⇒ vendor_unverified 恒为 true，结论必须带此标注；
 * - 版本取自范围约束下界（如 ^3.5.0）时，not_affected 降级为 unknown——
 *   不猜"实际安装的就是下界"，与项目"不猜测影响结论"红线一致。
 */
import { normalizeName, parseVersion, parseRange, satisfies } from "@safetrace/enrich";
import type { Component, ComponentMatch, Ecosystem } from "./types.js";

/** 情报侧最小形态（IntelItem 子集，便于测试与解耦）。 */
export interface IntelLite {
  intel_id: string;
  cve_ids: string[];
  entities: {
    product: string | null;
    vendor: string | null;
    version_range: string[];
  };
}

/** 带仓库来源的组件（存储行 → 匹配器输入的形态）。 */
export interface MatchedComponent extends Component {
  repo_path: string;
  /** 所属分组；缺省按未分组处理。 */
  group_id?: string;
}

/** 告警去重键：生态 + 归一化组件名。 */
export function componentKey(ecosystem: Ecosystem, name: string): string {
  return ecosystem + ":" + normalizeName(name);
}

/** 组件名的可比变体：npm 作用域包（@scope/name）同时尝试去掉作用域。 */
export function nameVariants(name: string): string[] {
  const variants = [normalizeName(name)];
  if (name.startsWith("@") && name.includes("/")) {
    variants.push(normalizeName(name.slice(name.indexOf("/") + 1)));
  }
  return variants.filter((v) => v !== "");
}

/**
 * P-03：版本影响判定的核心规则（组件扫描与问答入口共用同一实现，不引入第二套逻辑）。
 * 输入只依赖「情报侧版本规则 + 待判产品/版本」；ecosystem/来源路径等扫描形态由
 * matchComponent 包装层补齐，问答侧直接消费本函数的结构化结论。
 */
export interface VersionImpactInput {
  /** 待判产品名（任意写法，内部归一化后与情报产品标识比对）。 */
  name: string;
  /** 待判具体版本字面量；空串按 unknown 处理（不猜版本）。 */
  version: string;
  /** true = version 只是范围约束下界，结论需带 semver 提示。 */
  version_is_range_floor?: boolean;
  /** 原始约束原文（缺省表示用户直接给出的具体版本）。 */
  constraint_raw?: string;
}

export interface VersionImpactVerdict {
  intel_id: string;
  cve_ids: string[];
  /** 情报侧产品标识（未归一化原文）。 */
  product: string;
  /** 情报给出的受影响版本规则原文（OR 连接；无规则为 unavailable）。 */
  rule: string;
  status: "affected" | "not_affected" | "unknown";
  tested_version: string;
  matched_ranges: string[];
  /** 人类可读依据；unknown 时必须写明为什么无法判定。 */
  reason: string;
  /** 本地判定不携带厂商身份核实，恒为 true。 */
  vendor_unverified: boolean;
}

export function assessVersionImpact(item: IntelLite, input: VersionImpactInput): VersionImpactVerdict {
  const base = {
    intel_id: item.intel_id,
    cve_ids: [...item.cve_ids],
    product: item.entities.product ?? "",
    rule: item.entities.version_range.length ? item.entities.version_range.join(" OR ") : "unavailable",
    vendor_unverified: true,
  };
  const advisoryProduct = normalizeName(item.entities.product);
  const variants = nameVariants(input.name);

  if (!advisoryProduct || variants.length === 0) {
    return { ...base, status: "unknown", tested_version: input.version, matched_ranges: [], reason: "缺少可比较的产品标识" };
  }
  if (!variants.includes(advisoryProduct)) {
    return { ...base, status: "not_affected", tested_version: input.version, matched_ranges: [], reason: "产品标识不匹配" };
  }
  if (!input.version) {
    return { ...base, status: "unknown", tested_version: "", matched_ranges: [], reason: "未提供具体版本（约束 " + (input.constraint_raw || "缺失") + "）" };
  }
  const version = parseVersion(input.version);
  if (!version) {
    return { ...base, status: "unknown", tested_version: input.version, matched_ranges: [], reason: "版本格式不受支持：" + input.version };
  }
  const ranges = item.entities.version_range;
  if (ranges.length === 0) {
    return { ...base, status: "unknown", tested_version: input.version, matched_ranges: [], reason: "情报未提供受影响版本规则" };
  }

  let unsupportedRule = false;
  const matchedRanges: string[] = [];
  for (const range of ranges) {
    const constraints = parseRange(range);
    if (!constraints) {
      unsupportedRule = true;
      continue;
    }
    if (constraints.every((constraint) => satisfies(version, constraint))) matchedRanges.push(range);
  }

  if (matchedRanges.length > 0) {
    const caveat = input.version_is_range_floor
      ? "；版本取自范围约束下界（原约束 " + input.constraint_raw + "），实际安装版本可能更高"
      : "";
    return { ...base, status: "affected", tested_version: input.version, matched_ranges: matchedRanges, reason: "版本满足受影响版本规则（厂商身份未经本地核实）" + caveat };
  }
  if (unsupportedRule) {
    return { ...base, status: "unknown", tested_version: input.version, matched_ranges: [], reason: "至少一条版本规则无法解析，不能排除受影响" };
  }
  if (input.version_is_range_floor) {
    return { ...base, status: "unknown", tested_version: input.version, matched_ranges: [], reason: "版本为范围下界（原约束 " + input.constraint_raw + "），无法排除更高版本落入受影响区间" };
  }
  return { ...base, status: "not_affected", tested_version: input.version, matched_ranges: [], reason: "版本不在已解析的受影响版本范围内" };
}

export function matchComponent(item: IntelLite, component: MatchedComponent): ComponentMatch {
  const core = assessVersionImpact(item, component);
  return {
    component_key: componentKey(component.ecosystem, component.name),
    ecosystem: component.ecosystem,
    name: component.name,
    version: component.version,
    repo_path: component.repo_path,
    source_file: component.source_file,
    constraint_raw: component.constraint_raw,
    version_is_range_floor: component.version_is_range_floor,
    intel_id: item.intel_id,
    cve_ids: [...item.cve_ids],
    group_id: component.group_id ?? "adhoc",
    vendor_unverified: true,
    rule: core.rule,
    status: core.status,
    tested_version: core.tested_version,
    matched_ranges: core.matched_ranges,
    reason: core.reason,
  };
}

/** 产品名索引：归一化产品名 → 情报列表（避免全量组件×全量情报的双重循环）。 */
export function buildProductIndex(items: readonly IntelLite[]): Map<string, IntelLite[]> {
  const index = new Map<string, IntelLite[]>();
  for (const item of items) {
    const key = normalizeName(item.entities.product);
    if (!key) continue;
    const list = index.get(key);
    if (list) list.push(item);
    else index.set(key, [item]);
  }
  return index;
}

/** 批量匹配：只产出 affected（提醒只认命中；unknown/not_affected 不进提醒）。 */
export function matchComponents(items: readonly IntelLite[], components: readonly MatchedComponent[]): ComponentMatch[] {
  const index = buildProductIndex(items);
  const out: ComponentMatch[] = [];
  for (const component of components) {
    for (const variant of nameVariants(component.name)) {
      const candidates = index.get(variant);
      if (!candidates) continue;
      for (const item of candidates) {
        const match = matchComponent(item, component);
        if (match.status === "affected") out.push(match);
      }
    }
  }
  return out;
}
