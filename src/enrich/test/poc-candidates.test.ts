import { test } from "node:test";
import assert from "node:assert/strict";
import { extractPocCandidates, extractExploitReferences, type PocCandidateInput } from "../src/poc-candidates.js";

function input(payload: unknown, patch: Partial<PocCandidateInput> = {}): PocCandidateInput {
  return {
    intel_id: "intel_nvd_cve_2021_44228",
    cve_ids: ["CVE-2021-44228"],
    item: { title: "Log4Shell", entities: { product: "log4j", vendor: "apache" } },
    raw: { payload_ref: "tmp/nvd.json", source_id: "nvd_cve", url: "https://services.nvd.nist.gov/rest/json/cves/2.0", source_type: "nvd_cve" },
    payload_bytes: new TextEncoder().encode(JSON.stringify(payload)),
    payload_sha256: "a".repeat(64),
    parent_lineage_ids: ["ln_raw"],
    ...patch,
  };
}
const nvdLike = (refs: unknown[]) => ({ vulnerabilities: [{ cve: { id: "CVE-2021-44228", references: refs } }] });

test("only explicit Exploit/PoC tagged https references are kept", () => {
  const candidates = extractPocCandidates(input(nvdLike([
    { url: "https://example.test/exploit.py", tags: ["Exploit"] },
    { url: "https://example.test/poc.md", tags: ["PoC", "proof-of-concept"] },
    { url: "https://example.test/advisory", tags: ["Vendor Advisory"] },
    { url: "http://insecure.test/x", tags: ["Exploit"] },
    { url: "https://user:pw@example.test/x", tags: ["Exploit"] },
    { url: "https://example.test/exploitability", tags: ["exploitability discussion"] },
  ])));
  assert.deepEqual(candidates.map(c => c.reference_url), ["https://example.test/exploit.py", "https://example.test/poc.md"]);
  assert.deepEqual(candidates.map(c => c.evidence_kind), ["reference_tag_exploit", "reference_tag_poc"]);
  assert.ok(candidates.every(c => c.note.includes("NOT verified") && c.parent_lineage_ids.length === 1));
});

test("each CVE counts once, duplicate references dedupe, oversized reference list truncates", () => {
  const refs = Array.from({ length: 60 }, (_, i) => ({ url: "https://example.test/e" + i, tags: ["exploit"] }));
  const many = extractPocCandidates(input(nvdLike(refs), { cve_ids: ["CVE-2021-44228", "CVE-2021-45046"] }));
  assert.equal(many.length, 100, "two CVEs x 50-entry cap");
  assert.equal(new Set(many.map(c => c.candidate_id)).size, many.length);
});

test("missing lineage, hash mismatch and malformed JSON produce nothing", () => {
  assert.deepEqual(extractPocCandidates(input(nvdLike([{ url: "https://x.test/e", tags: ["exploit"] }]), { parent_lineage_ids: [] })), []);
  assert.deepEqual(extractPocCandidates(input(nvdLike([{ url: "https://x.test/e", tags: ["exploit"] }]), { payload_sha256: "bad" })), []);
  assert.deepEqual(extractExploitReferences(new TextEncoder().encode("not json")), []);
});

test("CVE.org containers.cna.references shape is supported", () => {
  const cveOrg = { containers: { cna: { references: [{ url: "https://example.test/cna-poc", tags: ["PoC"] }] } } };
  const candidates = extractPocCandidates(input(cveOrg));
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0]!.evidence_kind, "reference_tag_poc");
  assert.equal(candidates[0]!.cve_id, "CVE-2021-44228");
});