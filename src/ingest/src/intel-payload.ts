import type { IntelItem } from "@safetrace/shared";

/** Publish the frozen IntelItem shape only after DQ has inspected all internal per-source evidence. */
export function releasedIntelPayload(item: IntelItem): IntelItem {
  const keys: readonly (keyof IntelItem)[] = ["intel_id", "cve_ids", "ghsa_ids", "osv_ids", "aliases", "source_ids", "title", "summary",
    "published_at", "first_seen_at", "entities", "raw_refs", "source_reliability", "schema_version"];
  const payload = Object.fromEntries(keys.filter(key => item[key] !== undefined).map(key => [key, item[key]]));
  return payload as unknown as IntelItem;
}
