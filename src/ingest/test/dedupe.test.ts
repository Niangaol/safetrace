/** Y3 强标识归并单测。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { IntelItem } from "@safetrace/shared";
import { dedupeAll, mergeIntelItems, sharedIdFields } from "../src/dedupe.js";

function baseItem(over: Partial<IntelItem> = {}): IntelItem {
  return {
    intel_id: "intel_a",
    cve_ids: ["CVE-2021-44228"],
    source_ids: ["cisa_kev"],
    title: "短标题",
    published_at: "2021-12-10T00:00:00Z",
    first_seen_at: "2026-09-28T10:00:00Z",
    entities: {
      product: "log4j-core",
      vendor: "apache",
      version_range: ["<=2.14.1"],
      cwe: ["CWE-917"],
      cpes: [],
    },
    raw_refs: ["a.json"],
    source_reliability: 0.9,
    schema_version: "1.0",
    ...over,
  };
}

test("dedupe：强标识交集才合并，保留多源、最早 first_seen、最长 title/summary", () => {
  const a = baseItem();
  const b = baseItem({
    intel_id: "intel_b",
    source_ids: ["nvd_cve"],
    first_seen_at: "2026-09-27T09:00:00Z", // 更早
    title: "更长的标题标题标题",
    summary: "b 侧摘要更完整",
    raw_refs: ["b.json"],
    entities: {
      product: null,
      vendor: null,
      version_range: ["<2.15.0"],
      cwe: ["CWE-502"],
      cpes: ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
    },
    source_reliability: 0.95,
  });
  const { merged, link } = mergeIntelItems(a, b);
  assert.ok(link !== null);
  assert.equal(link!.algorithm, "strong_id_exact");
  assert.deepEqual(link!.evidence.matched_fields, ["cve_ids"]);
  assert.equal(link!.from_intel_id, "intel_b");
  assert.equal(link!.to_intel_id, "intel_a");
  assert.deepEqual(merged.source_ids, ["cisa_kev", "nvd_cve"]); // 多源并集
  assert.equal(merged.first_seen_at, "2026-09-27T09:00:00Z"); // 更早者
  assert.equal(merged.published_at, "2021-12-10T00:00:00Z");
  assert.equal(merged.title, "更长的标题标题标题"); // 更长者
  assert.equal(merged.summary, "b 侧摘要更完整");
  assert.equal(merged.intel_id, "intel_a"); // 单调归并保留 existing 身份
  assert.equal(merged.entities.product, "log4j-core"); // a 有值取 a
  assert.equal(merged.entities.vendor, "apache");
  assert.deepEqual(merged.entities.version_range, ["<=2.14.1", "<2.15.0"]); // 并集
  assert.deepEqual(merged.entities.cwe, ["CWE-917", "CWE-502"]);
  assert.equal(merged.entities.cpes.length, 1);
  assert.deepEqual(merged.raw_refs, ["a.json", "b.json"]);
  assert.equal(merged.source_reliability, 0.95); // 取更可靠源
});

test("dedupe：无强标识交集不误合（link=null，merged 原样返回）", () => {
  const a = baseItem();
  const b = baseItem({ intel_id: "intel_b", cve_ids: ["CVE-2022-9999"] });
  const { merged, link } = mergeIntelItems(a, b);
  assert.equal(link, null);
  assert.equal(merged, a);
  assert.deepEqual(sharedIdFields(a, b), []);
});

test("dedupe：ghsa/osv 标识交集同样触发合并", () => {
  const a = baseItem({ cve_ids: [], ghsa_ids: ["GHSA-jfh8-c2jp-5v3q"] });
  const b = baseItem({ intel_id: "intel_b", cve_ids: ["CVE-2021-44228"], ghsa_ids: ["GHSA-jfh8-c2jp-5v3q"] });
  const { merged, link } = mergeIntelItems(a, b);
  assert.ok(link !== null);
  assert.deepEqual(link!.evidence.matched_fields, ["ghsa_ids"]);
  assert.deepEqual(merged.cve_ids, ["CVE-2021-44228"]);
  assert.deepEqual(merged.source_ids, ["cisa_kev"]);
});

test("dedupe：batch 版把同漏洞多源折叠为一条并记录 link", () => {
  const a = baseItem();
  const b = baseItem({ intel_id: "intel_b", source_ids: ["nvd_cve"] });
  const c = baseItem({ intel_id: "intel_c", cve_ids: ["CVE-2022-0001"], source_ids: ["osv"] });
  const { items, links } = dedupeAll([a, b, c]);
  assert.equal(items.length, 2);
  assert.equal(links.length, 1);
  assert.deepEqual(links[0]!.evidence.matched_fields, ["cve_ids"]);
  const folded = items.find((i) => i.intel_id === "intel_a");
  assert.ok(folded !== undefined);
  assert.deepEqual(folded!.source_ids, ["cisa_kev", "nvd_cve"]);
  assert.ok(items.some((i) => i.intel_id === "intel_c")); // 无交集条目独立保留
});
