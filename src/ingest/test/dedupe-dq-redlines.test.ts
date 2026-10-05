import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import type { IntelItem } from "@safetrace/shared";
import { dedupeAll, mergeIntelItems } from "../src/dedupe.js";
import { assessQualityVerdict } from "../src/dq1.js";
import { releasedIntelPayload } from "../src/intel-payload.js";

async function item(id: string, extras: Record<string, unknown> = {}): Promise<IntelItem> {
  const clean = JSON.parse(await readFile(new URL("../../../fixtures/intelitem.sample.json", import.meta.url), "utf8"));
  return { ...clean, intel_id: id, source_ids: [id], raw_refs: [id + ".json"], ...extras };
}
const now = new Date("2026-10-04T00:00:00Z");
function verdict(value: IntelItem) { return assessQualityVerdict(value, { now }); }

for (const status of ["REJECT", "REJECTED", "RESERVED", "DISPUTED", " rejected ", "Reserved pending"]) {
  test("dedupe/DQ keeps status redline in either order: " + status, async () => {
    const a = await item("kev");
    const b = await item("nvd", { _cve_status: status });
    for (const inputs of [[a, b], [b, a]]) {
      const before = structuredClone(inputs);
      const folded = dedupeAll(inputs).items[0]!;
      assert.equal(verdict(folded).verdict, "quarantine");
      assert.ok(verdict(folded).flags.includes("reject_status"));
      assert.deepEqual(inputs, before, "inputs must not be mutated");
      const roundtrip = JSON.parse(JSON.stringify(mergeIntelItems(folded, await item("osv")).merged));
      assert.equal(verdict(roundtrip).verdict, "quarantine", "later clean merge/serialization cannot wash redline");
      const sources = (roundtrip as { _dq_sources: Array<{ source_ids: string[]; _cve_status?: string }> })._dq_sources;
      assert.ok(sources.some((source) => source.source_ids.includes("nvd") && source._cve_status === status));
    }
  });
}

test("dedupe/DQ cannot borrow another source's POC hash", async () => {
  const a = await item("dead", { poc_link: "https://example.test/poc" });
  const b = await item("verified", { poc_link: "https://example.test/poc", poc_sha256: "a".repeat(64) });
  const c = await item("hash-only", { poc_sha256: "b".repeat(64) });
  for (const inputs of [[a, b, c], [b, c, a], [c, a, b], [a, c, b], [b, a, c], [c, b, a]]) {
    const folded = JSON.parse(JSON.stringify(dedupeAll(inputs).items[0]));
    assert.equal(verdict(folded).verdict, "quarantine");
    assert.ok(verdict(folded).flags.includes("poc_dead_link"));
  }
  assert.equal(verdict(b).verdict, "pass", "a valid source-local pair remains compatible");
});

for (const extras of [
  { _cve_status: "UNKNOWN_STATE" }, { _cve_status: null }, { _cve_status: ["REJECTED"] },
  { _cve_status: "" }, { poc_link: { url: "https://example.test/poc" } },
  { poc_link: "https://example.test/poc", poc_sha256: "not-a-hash" },
  { poc_link: "https://example.test/poc", poc_sha256: null },
  { _dq_sources: null }, { _dq_sources: [] }, { _dq_sources: [{}] },
  { _dq_sources: ["REJECTED"] },
  { _dq_sources: [{ intel_id: "x", source_ids: ["x"], raw_refs: ["x.json"], new_status: "REJECTED" }] },
]) {
  test("DQ fail-closed unknown metadata " + JSON.stringify(extras), async () => {
    const dirty = await item("dirty", extras);
    assert.equal(verdict(dirty).verdict, "quarantine");
    for (const inputs of [[await item("clean"), dirty], [dirty, await item("clean")]]) {
      assert.equal(verdict(dedupeAll(inputs).items[0]!).verdict, "quarantine");
    }
  });
}

test("DQ accepts compatible authority workflow states without washing redlines", async () => {
  const a = await item("a", { _cve_status: "PUBLISHED" });
  const b = await item("b", { _cve_status: "Analyzed" });
  for (const inputs of [[a, b], [b, a]]) {
    assert.equal(verdict(dedupeAll(inputs).items[0]!).verdict, "pass");
  }
  for (const inputs of [[a, await item("c", { _cve_status: " published " })], [await item("clean"), a]]) {
    const v = verdict(dedupeAll(inputs).items[0]!);
    assert.equal(v.verdict, "pass");
    assert.deepEqual(v.flags, []);
  }
});

test("dedupe preserves two valid source-local POC pairs without changing scalar types", async () => {
  const a = await item("a", { poc_link: "https://example.test/a", poc_sha256: "a".repeat(64) });
  const b = await item("b", { poc_link: "https://example.test/b", poc_sha256: "b".repeat(64) });
  for (const inputs of [[a, b], [b, a]]) {
    const folded = dedupeAll(inputs).items[0]!;
    const v = verdict(JSON.parse(JSON.stringify(folded)));
    assert.equal(v.verdict, "pass");
    assert.deepEqual(v.flags, []);
    assert.equal(typeof (folded as unknown as Record<string, unknown>).poc_link, "string");
    assert.equal(typeof (folded as unknown as Record<string, unknown>).poc_sha256, "string");
  }
});

test("dedupe does not transfer redlines across unrelated identifiers", async () => {
  const a = await item("a");
  const b = await item("b", { cve_ids: ["CVE-2026-99999"], ghsa_ids: [], _cve_status: "REJECTED" });
  assert.equal(mergeIntelItems(a, b).merged, a);
  assert.equal(verdict(a).verdict, "pass");
  assert.equal(dedupeAll([a, b]).items.length, 2);
});

test("published IntelItem excludes DQ-only extras without erasing audit input", async () => {
  const a = await item("a", { _cve_status: "PUBLISHED", poc_link: "https://example.test/a", poc_sha256: "a".repeat(64) });
  const b = await item("b", { _cve_status: "Analyzed" });
  const merged = dedupeAll([a,b]).items[0]!; const before = structuredClone(merged);
  assert.equal(verdict(merged).verdict, "pass");
  const payload = releasedIntelPayload(merged);
  for (const key of ["_dq_sources", "_cve_status", "poc_link", "poc_sha256"]) assert.equal(key in payload, false);
  assert.deepEqual(merged, before); assert.equal("_dq_sources" in merged, true);
  assert.deepEqual(payload.source_ids, merged.source_ids);
});
