import type { IntelItem } from "@safetrace/shared";

/** 一条明确给定的静态演示资产；本模块不发现资产，也不进行探测。 */
export interface DemoAsset {
  asset_id: string;
  product: string;
  vendor: string | null;
  version: string;
  service: string;
  criticality: "critical" | "high" | "medium" | "low";
}

export type AssetImpact = "affected" | "not_affected" | "unknown";

export interface AssetMatch {
  asset_id: string;
  service: string;
  criticality: DemoAsset["criticality"];
  status: AssetImpact;
  evidence: {
    intel_id: string;
    cve_ids: string[];
    rule: string;
    tested_version: string;
    matched_ranges: string[];
    reason: string;
  };
}

type Version = bigint[];
type Constraint = { operator: "<" | "<=" | ">" | ">=" | "="; version: Version };

/**
 * 对 IntelItem 与显式传入的资产清单做确定性比较。产品名只做大小写和标点归一，
 * 不做别名或模糊匹配，不联网发现或探测。版本规则不支持或信息不完整时返回 unknown，
 * 不猜测影响结论。
 */
export function matchAssets(
  item: Pick<IntelItem, "intel_id" | "cve_ids" | "entities">,
  assets: readonly DemoAsset[],
): AssetMatch[] {
  return assets.map((asset) => matchOne(item, asset));
}

function matchOne(item: Pick<IntelItem, "intel_id" | "cve_ids" | "entities">, asset: DemoAsset): AssetMatch {
  const product = normalizeName(item.entities.product);
  const assetProduct = normalizeName(asset.product);
  const ranges = item.entities.version_range;

  if (!product || !assetProduct) {
    return result(item, asset, "unknown", ranges, [], "缺少可比较的产品标识");
  }
  if (product !== assetProduct) {
    return result(item, asset, "not_affected", ranges, [], "产品标识不匹配");
  }

  const advisoryVendor = normalizeName(item.entities.vendor);
  const assetVendor = normalizeName(asset.vendor);
  if (!advisoryVendor || !assetVendor) {
    return result(item, asset, "unknown", ranges, [], "缺少一侧厂商标识，需核实产品身份");
  }
  if (advisoryVendor !== assetVendor) {
    return result(item, asset, "unknown", ranges, [], "产品名相同但厂商不一致，需核实产品身份");
  }

  const version = parseVersion(asset.version);
  if (!version) return result(item, asset, "unknown", ranges, [], "资产版本格式不受支持或缺失");
  if (ranges.length === 0) return result(item, asset, "unknown", ranges, [], "情报未提供受影响版本规则");

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

  if (matchedRanges.length > 0) return result(item, asset, "affected", ranges, matchedRanges, "资产版本满足受影响版本规则");
  if (unsupportedRule) return result(item, asset, "unknown", ranges, [], "至少一条版本规则无法解析，不能排除受影响");
  return result(item, asset, "not_affected", ranges, [], "资产版本不在已解析的受影响版本范围内");
}

function result(
  item: Pick<IntelItem, "intel_id" | "cve_ids">,
  asset: DemoAsset,
  status: AssetImpact,
  ranges: string[],
  matchedRanges: string[],
  reason: string,
): AssetMatch {
  return {
    asset_id: asset.asset_id,
    service: asset.service,
    criticality: asset.criticality,
    status,
    evidence: {
      intel_id: item.intel_id,
      cve_ids: [...item.cve_ids],
      rule: ranges.length ? ranges.join(" OR ") : "unavailable",
      tested_version: asset.version,
      matched_ranges: matchedRanges,
      reason,
    },
  };
}

function normalizeName(value: string | null): string {
  return value?.normalize("NFKC").toLocaleLowerCase("en-US").replace(/[^a-z0-9]/g, "") ?? "";
}

/** 仅接受数字点分版本；预发布、构建号及生态专用版本均保持 unknown。 */
function parseVersion(value: string): Version | null {
  const normalized = value.trim().replace(/^v(?=\d)/i, "");
  if (!/^\d+(?:\.\d+){0,7}$/.test(normalized)) return null;
  try {
    return normalized.split(".").map((part) => BigInt(part));
  } catch {
    return null;
  }
}

/** 单条范围中的比较条件按 AND 处理；数组中的多条范围按 OR 处理。 */
function parseRange(value: string): Constraint[] | null {
  const tokens = value.replaceAll(",", " ").trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  const constraints: Constraint[] = [];
  for (const token of tokens) {
    const match = /^(<=|>=|<|>|=)?v?(\d+(?:\.\d+){0,7})$/i.exec(token);
    if (!match) return null;
    const versionText = match[2];
    if (!versionText) return null;
    const version = parseVersion(versionText);
    if (!version) return null;
    const operator = (match[1] ?? "=") as Constraint["operator"];
    constraints.push({ operator, version });
  }
  return isSatisfiable(constraints) ? constraints : null;
}

function isSatisfiable(constraints: Constraint[]): boolean {
  let equality: Version | undefined;
  let lower: { version: Version; inclusive: boolean } | undefined;
  let upper: { version: Version; inclusive: boolean } | undefined;
  for (const constraint of constraints) {
    if (constraint.operator === "=") {
      if (equality && compareVersions(equality, constraint.version) !== 0) return false;
      equality = constraint.version;
    } else if (constraint.operator === ">" || constraint.operator === ">=") {
      const inclusive = constraint.operator === ">=";
      const comparison = lower ? compareVersions(constraint.version, lower.version) : 1;
      if (!lower || comparison > 0 || (comparison === 0 && !inclusive)) lower = { version: constraint.version, inclusive };
    } else {
      const inclusive = constraint.operator === "<=";
      const comparison = upper ? compareVersions(constraint.version, upper.version) : -1;
      if (!upper || comparison < 0 || (comparison === 0 && !inclusive)) upper = { version: constraint.version, inclusive };
    }
  }
  if (equality) return constraints.every((constraint) => satisfies(equality!, constraint));
  if (!lower || !upper) return true;
  const comparison = compareVersions(lower.version, upper.version);
  return comparison < 0 || (comparison === 0 && lower.inclusive && upper.inclusive);
}

function compareVersions(left: Version, right: Version): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const a = left[index] ?? 0n;
    const b = right[index] ?? 0n;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

function satisfies(version: Version, constraint: Constraint): boolean {
  const comparison = compareVersions(version, constraint.version);
  switch (constraint.operator) {
    case "<": return comparison < 0;
    case "<=": return comparison <= 0;
    case ">": return comparison > 0;
    case ">=": return comparison >= 0;
    case "=": return comparison === 0;
  }
}
