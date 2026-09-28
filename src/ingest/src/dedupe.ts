/**
 * Y3 · 强标识归并：cve_ids/ghsa_ids/osv_ids 有交集才合并（无交集不误合）。
 * 归并是单调操作（只合并不拆）：保留全部 source_ids 与最早 first_seen_at，
 * title/summary 取更长者，entities 字段取并集，merged 沿用 existing 的 intel_id。
 * 姊妹 CVE（无共享 ID）不做自动合并，只建 DuplicateLink 关系（本版仅在真正合并时产出 link）。
 */
import { parseLoose } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";

/** 归并证据链（对齐 02-report Y3 契约；S2 暂无专属主题，由 pipeline 内部消费）。 */
export interface DuplicateLink {
  from_intel_id: string;
  to_intel_id: string;
  algorithm: string;
  confidence: number;
  evidence: { matched_fields: string[]; sim_score: number };
}

const ID_FIELDS = ["cve_ids", "ghsa_ids", "osv_ids"] as const;
export const DEDUPE_ALGORITHM = "strong_id_exact";

/** 两个 IntelItem 在哪些强标识数组上有交集（合并判据）。 */
export function sharedIdFields(a: IntelItem, b: IntelItem): string[] {
  const matched: string[] = [];
  for (const field of ID_FIELDS) {
    const av = a[field] ?? [];
    const bv = b[field] ?? [];
    if (av.some((x) => bv.includes(x))) matched.push(field);
  }
  return matched;
}

function union(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

/** 可空数组合并：两侧皆空返回 undefined（不制造空数组字段）。 */
function unionOpt(a: string[] | undefined, b: string[] | undefined): string[] | undefined {
  const merged = union(a ?? [], b ?? []);
  return merged.length > 0 ? merged : undefined;
}

function longer(a: string, b: string): string {
  return b.length > a.length ? b : a;
}

/** 取更早的可解析时间；解析不了保守保留 existing。 */
function earlier(a: string, b: string): string {
  const at = parseLoose(a);
  const bt = parseLoose(b);
  if (at !== null && bt !== null) return bt < at ? b : a;
  return a;
}

function mergeEntities(a: IntelItem["entities"], b: IntelItem["entities"]): IntelItem["entities"] {
  return {
    product: a.product ?? b.product,
    vendor: a.vendor ?? b.vendor,
    version_range: union(a.version_range, b.version_range),
    cwe: union(a.cwe, b.cwe),
    cpes: union(a.cpes, b.cpes),
  };
}

/** 合并两条 IntelItem；无强标识交集时返回原 existing 且 link=null（不误合）。 */
export function mergeIntelItems(
  existing: IntelItem,
  incoming: IntelItem,
): { merged: IntelItem; link: DuplicateLink | null } {
  const matched = sharedIdFields(existing, incoming);
  if (matched.length === 0) return { merged: existing, link: null };
  const merged: IntelItem = {
    ...existing,
    cve_ids: union(existing.cve_ids, incoming.cve_ids),
    ...(unionOpt(existing.ghsa_ids, incoming.ghsa_ids) ? { ghsa_ids: unionOpt(existing.ghsa_ids, incoming.ghsa_ids) } : {}),
    ...(unionOpt(existing.osv_ids, incoming.osv_ids) ? { osv_ids: unionOpt(existing.osv_ids, incoming.osv_ids) } : {}),
    ...(unionOpt(existing.aliases, incoming.aliases) ? { aliases: unionOpt(existing.aliases, incoming.aliases) } : {}),
    source_ids: union(existing.source_ids, incoming.source_ids),
    title: longer(existing.title, incoming.title),
    ...(existing.summary !== undefined || incoming.summary !== undefined
      ? { summary: longer(existing.summary ?? "", incoming.summary ?? "") }
      : {}),
    published_at: earlier(existing.published_at, incoming.published_at),
    first_seen_at: earlier(existing.first_seen_at, incoming.first_seen_at),
    entities: mergeEntities(existing.entities, incoming.entities),
    raw_refs: union(existing.raw_refs, incoming.raw_refs),
    source_reliability: Math.max(existing.source_reliability, incoming.source_reliability),
  };
  return {
    merged,
    link: {
      from_intel_id: incoming.intel_id,
      to_intel_id: existing.intel_id,
      algorithm: DEDUPE_ALGORITHM,
      confidence: 1,
      evidence: { matched_fields: matched, sim_score: 1 },
    },
  };
}

export interface DedupeResult {
  items: IntelItem[];
  links: DuplicateLink[];
}

/** 批量归并：按强标识建索引，同漏洞多源报道折叠为单一 IntelItem（O(n)）。 */
export function dedupeAll(items: IntelItem[]): DedupeResult {
  const out: IntelItem[] = [];
  const index = new Map<string, number>();
  const links: DuplicateLink[] = [];
  for (const item of items) {
    const ids = union(item.cve_ids ?? [], union(item.ghsa_ids ?? [], item.osv_ids ?? []));
    let hit = -1;
    for (const id of ids) {
      const at = index.get(id);
      if (at !== undefined) {
        hit = at;
        break;
      }
    }
    if (hit >= 0) {
      const existing = out[hit];
      if (existing === undefined) continue;
      const { merged, link } = mergeIntelItems(existing, item);
      out[hit] = merged;
      if (link !== null) {
        links.push(link);
        for (const id of ids) index.set(id, hit);
      }
    } else {
      out.push(item);
      const at = out.length - 1;
      for (const id of ids) index.set(id, at);
    }
  }
  return { items: out, links };
}
