import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IntelItem } from "@safetrace/shared";
import { loadScoreSourcesFromRawRefs } from "../src/f4-cvss.js";

const HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N";
async function readScores(doc: unknown, cve = "CVE-2021-44228") {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-score-identity-"));
  const ref = join(dir, "raw.json");
  try {
    await writeFile(ref, JSON.stringify(doc));
    const item: IntelItem = {
      intel_id: "intel_target", cve_ids: [cve], source_ids: ["nvd_cve"], title: "target",
      published_at: "2021-12-10T10:00:00Z", first_seen_at: "2026-10-03T12:00:00Z",
      entities: { product: "test", vendor: "test", version_range: [], cwe: [], cpes: [] },
      raw_refs: [ref], source_reliability: 0.9, schema_version: "1.0",
    };
    return await loadScoreSourcesFromRawRefs(item);
  } finally { await rm(dir, { recursive: true, force: true }); }
}
const nvd = (id: string | undefined, vectorString: string, baseScore: number) => ({
  cve: { id, metrics: { cvssMetricV31: [{ cvssData: { vectorString, baseScore } }] } },
});

test("raw scoring selects the target CVE instead of the first NVD record", async () => {
  const scores = await readScores({ vulnerabilities: [nvd("CVE-2024-0001", HIGH, 10), nvd("CVE-2021-44228", LOW, 3.7)] });
  assert.equal(scores.length, 1);
  assert.equal(scores[0]!.cvss_v3_base, 3.7);
  assert.equal(scores[0]!.cvss_v3_vector, LOW);
});

test("raw scoring rejects unrelated or identity-free NVD metrics", async () => {
  assert.deepEqual(await readScores({ vulnerabilities: [nvd("CVE-2024-0001", HIGH, 10), nvd(undefined, HIGH, 10)] }), []);
});

test("raw scoring matches OSV CVE aliases before collecting severity", async () => {
  const scores = await readScores({ results: [{ vulns: [
    { id: "GHSA-unrelated", aliases: ["CVE-2024-0001"], severity: [{ type: "CVSS_V3", score: HIGH }] },
    { id: "GHSA-target", aliases: ["CVE-2021-44228"], severity: [{ type: "CVSS_V3", score: LOW }] },
  ] }] });
  assert.equal(scores.length, 1);
  assert.equal(scores[0]!.cvss_v3_vector, LOW);
});

test("CVE-ORG scoring requires matching identity and supports ADP arrays", async () => {
  const doc = { cveMetadata: { cveId: "CVE-2021-44228" }, containers: {
    cna: { metrics: [{ cvssV3_1: { vectorString: LOW, baseScore: 3.7 } }] },
    adp: [{ metrics: [{ cvssV3_1: { vectorString: HIGH, baseScore: 10 } }] }],
  } };
  assert.deepEqual((await readScores(doc)).map(s => s.source_of_score), ["cna", "adp"]);
  assert.deepEqual(await readScores(doc, "CVE-2024-0001"), []);
});
