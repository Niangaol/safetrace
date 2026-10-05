/** 全部 HTTP 为内存 fixture mock；事件与 payload 缓存只写临时目录。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { MemoryEventStore } from "@safetrace/shared";
import type { IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { runIngestOnce } from "../src/pipeline.js";

test("pipeline mocked adapters → dedupe → DQ blocks incoming redlines from either authority", async () => {
  const cache = await mkdtemp(path.join(tmpdir(), "safetrace-dedupe-dq-"));
  const keys = ["OFFLINE_FIXTURES", "SAFETRACE_CACHE_DIR", "NVD_API_KEY"] as const;
  const saved = keys.map((key) => process.env[key]);
  const oldFetch = globalThis.fetch;
  process.env.OFFLINE_FIXTURES = "false";
  process.env.SAFETRACE_CACHE_DIR = cache;
  process.env.NVD_API_KEY = "mock-only-no-network";
  const fixture = async (name: string) => JSON.parse(await readFile(new URL("../../../fixtures/sources/" + name + ".sample.json", import.meta.url), "utf8"));
  const kev = await fixture("kev");
  const nvd = await fixture("nvd");
  const cveorg = await fixture("cveorg");
  try {
    for (const authority of ["nvd_cve", "cve_org"]) {
      for (const status of ["REJECTED", "RESERVED", "DISPUTED"]) {
        const n = structuredClone(nvd);
        const c = structuredClone(cveorg);
        if (authority === "nvd_cve") n.vulnerabilities[0].cve.vulnStatus = status;
        else c.cveMetadata.state = status;
        const calls: string[] = [];
        globalThis.fetch = (async (input: string | URL | Request) => {
          const url = String(input);
          calls.push(url);
          const body = url.includes("known_exploited_vulnerabilities") ? kev :
            url.includes("services.nvd.nist.gov") ? n :
            url.includes("cveawg.mitre.org") ? c : undefined;
          assert.notEqual(body, undefined, "unexpected URL must not call real fetch: " + url);
          return new Response(JSON.stringify(body), { status: 200 });
        }) as typeof fetch;
        const store = new MemoryEventStore();
        const result = await runIngestOnce({ store, offline: false, sourceIds: ["cisa_kev", "nvd_cve", "cve_org"], limit: 1 });
        assert.ok(calls.length >= 3);
        assert.equal(result.parsed.length, 3);
        assert.equal(result.merged.length, 1);
        assert.equal(result.merged[0]!.intel_id, "intel_kev_cve_2021_44228");
        assert.equal(result.verdicts[0]!.verdict, "quarantine", authority + ":" + status);
        assert.ok(result.verdicts[0]!.flags.includes("reject_status"));
        assert.equal((await store.read<IntelItem>("intel.items")).length, 0, "quarantine never published as intel");
        const verdicts = await store.read<QualityVerdict>("dq.verdicts");
        assert.equal(verdicts.length, 1);
        assert.equal(verdicts[0]!.payload.verdict, "quarantine");
        assert.equal((await store.read<RawDoc>("raw.docs")).length, 3);
        const lineage = await store.readLineage(result.trace_id);
        assert.equal(lineage.filter((row) => row.stage === "ingest.parse").length, 3);
        const dq = lineage.find((row) => row.stage === "ingest.dq1")!;
        assert.ok(dq.parent_lineage_ids.length >= 4, "DQ retains multi-source and merge ancestry");
        assert.ok(dq.output_refs.some((ref) => ref.kind === "QualityVerdict" && /^[a-f0-9]{64}$/.test(ref.sha256 ?? "")));
        assert.ok(result.fetched.every((raw) => path.resolve(raw.payload_ref).startsWith(cache)), "all payloads use disposable cache");
      }
    }
  } finally {
    globalThis.fetch = oldFetch;
    keys.forEach((key, index) => { if (saved[index] === undefined) delete process.env[key]; else process.env[key] = saved[index]; });
    await rm(cache, { recursive: true, force: true });
  }
});

test("pipeline publishes only frozen IntelItem fields while retaining compatible source statuses for DQ audit", async () => {
  const cache = await mkdtemp(path.join(tmpdir(), "safetrace-dq-publish-"));
  const keys = ["OFFLINE_FIXTURES", "SAFETRACE_CACHE_DIR", "NVD_API_KEY"] as const;
  const saved = keys.map(key => process.env[key]); const oldFetch = globalThis.fetch;
  process.env.OFFLINE_FIXTURES = "false"; process.env.SAFETRACE_CACHE_DIR = cache; process.env.NVD_API_KEY = "mock";
  const fixture = async (name: string) => JSON.parse(await readFile(new URL("../../../fixtures/sources/" + name + ".sample.json", import.meta.url), "utf8"));
  const kev = await fixture("kev"), nvd = await fixture("nvd"), cveorg = await fixture("cveorg");
  nvd.vulnerabilities[0].cve.vulnStatus = "Analyzed"; cveorg.cveMetadata.state = "PUBLISHED";
  try {
    globalThis.fetch = (async input => {
      const url = String(input); const body = url.includes("known_exploited") ? kev : url.includes("services.nvd") ? nvd : url.includes("cveawg") ? cveorg : undefined;
      assert.ok(body, "unexpected external request"); return Response.json(body);
    }) as typeof fetch;
    const store = new MemoryEventStore();
    const result = await runIngestOnce({ store, offline: false, sourceIds: ["cisa_kev", "nvd_cve", "cve_org"], limit: 1 });
    assert.equal(result.verdicts[0]!.verdict, "pass", "compatible published/analysis workflow states must not be quarantined");
    const nvdRaw = result.fetched.find(raw => raw.source_id === "nvd_cve")!;
    const cveRaw = result.fetched.find(raw => raw.source_id === "cve_org")!;
    assert.match(await readFile(nvdRaw.payload_ref, "utf8"), /Analyzed/);
    assert.match(await readFile(cveRaw.payload_ref, "utf8"), /PUBLISHED/);
    const events = await store.read<IntelItem>("intel.items"); assert.equal(events.length, 1);
    for (const key of ["_cve_status", "_dq_sources", "poc_link", "poc_sha256"]) assert.equal(key in events[0]!.payload, false);
    const verdict = (await store.read<QualityVerdict>("dq.verdicts"))[0]!;
    assert.equal(verdict.causation_id, events[0]!.event_id); assert.equal(verdict.payload.gate_version, "1.0.1");
  } finally {
    globalThis.fetch = oldFetch;
    keys.forEach((key, i) => { if (saved[i] === undefined) delete process.env[key]; else process.env[key] = saved[i]; });
    await rm(cache, { recursive: true, force: true });
  }
});
