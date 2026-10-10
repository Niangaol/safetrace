/** 完整 CVE/允许列表产品身份；不使用编号前缀或模糊相似度判断覆盖。 */
import { canonicalProductName, productNameAliases } from "./q1-intent.js";
export function evidenceCveIds(text: string): string[] {
  return [...new Set((text.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map(id => id.toUpperCase()))];
}
export function coversProducts(products: readonly string[], texts: readonly string[]): boolean {
  const haystack = texts.join("\n").toLowerCase();
  return products.every(product => productNameAliases(canonicalProductName(product)).some(alias => {
    const slash = String.fromCharCode(92);
    const escaped = [...alias].map(c => (".*+?^${}()|[]" + slash).includes(c) ? slash + c : c).join("");
    return new RegExp("(?:^|[^a-z0-9])" + escaped + "(?:$|[^a-z0-9])", "i").test(haystack);
  }));
}
