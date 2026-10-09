import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { SqliteExtensionReceiptStore, validateExtensionReceipt } from "../src/extension-receipts.js";
import { preparePocReceipt, commitPocReceipt, readPocCandidates } from "../src/poc-extension.js";
import type { IntelItem } from "@safetrace/shared";

const PROVENANCE = { model: "Qwen/Qwen3.5-2B", checkpoint_sha256: "c".repeat(64), base_revision: "15852e8c16360a2fea060d615a32b45270f8a8fc", code_commit: "80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee", device: "cuda:0" };
const jevAnswer = (related: number) => ({ model: PROVENANCE.model, metadata: { method: "lora_decision_head", checkpoint_sha256: PROVENANCE.checkpoint_sha256, base_revision: PROVENANCE.base_revision, code_commit: PROVENANCE.code_commit, device: PROVENANCE.device }, answers: { relevance: { type: "choice", choice: related >= 0.5 ? "related" : "unrelated", probabilities: { related, unrelated: Number((1 - related).toFixed(6)), uncertain: 0 }, confidence: Math.max(related, 1 - related) } } });

async function fixture(run: (f: { root: string; path: string; events: SqliteEventStore; bus: EventBus; item: IntelItem; rawPath: string }) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "poc-extension-")), path = join(root, "intel.sqlite");
  const events = new SqliteEventStore(path), bus = new EventBus({ store: events });
  const original = fetch, keys = ["OFFLINE_FIXTURES", "SAFETRACE_CACHE_DIR", "NVD_API_KEY"] as const, saved = keys.map(k => process.env[k]);
  try {
    process.env.OFFLINE_FIXTURES = "false"; process.env.SAFETRACE_CACHE_DIR = root; process.env.NVD_API_KEY = "mock";
    const payload = { resultsPerPage: 1, startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: "CVE-2026-1001", sourceIdentifier: "security@example.org", published: "2026-10-01T00:00:00.000", lastModified: "2026-10-01T00:00:00.000", vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: "Vue before 3.5.0 allows script injection." }], weaknesses: [{ source: "nvd@nist.gov", type: "Primary", description: [{ lang: "en", value: "CWE-79" }] }], metrics: {}, references: [{ url: "https://example.test/exploit.py", source: "security@example.org", tags: ["Exploit"] }, { url: "https://example.test/advisory", source: "security@example.org", tags: ["Vendor Advisory"] }] } }] };
    globalThis.fetch = (async () => Response.json(payload)) as typeof fetch;
    await runIngestOnce({ store: events, offline: false, sourceIds: ["nvd_cve"], limit: 1 });
    globalThis.fetch = (async () => { throw new Error("PoC extension must not fetch reference content"); }) as typeof fetch;
    const item = [...readIntelIndexSnapshot(path).accepted.values()][0]!.item;
    const rawPath = [...readIntelIndexSnapshot(path).accepted.values()][0]!.item.raw_refs[0]!;
    await run({ root, path, events, bus, item, rawPath });
  } finally {
    globalThis.fetch = original; keys.forEach((k, i) => { if (saved[i] === undefined) delete process.env[k]; else process.env[k] = saved[i]; }); events.close(); await rm(root, { recursive: true, force: true });
  }
}

test("PoC 候选只来自已验证原文，模型建议附带 provenance 且永不当事实", async () => {
  await fixture(async f => {
    const store = new SqliteExtensionReceiptStore(f.path);
    try {
      const receipt = await preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "Open-Jev-2B@0c7aa49", jevBaseUrl: "http://127.0.0.1:8791", jevProvenance: PROVENANCE, fetchImpl: (async () => Response.json(jevAnswer(0.97))) as typeof fetch });
      assert.equal(receipt.artifacts.length, 1, "只收 Exploit 标签引用");
      assert.equal(receipt.artifacts[0]!.evidence_kind, "reference_tag_exploit");
      assert.equal(receipt.advisories.length, 1);
      assert.equal(receipt.advisories[0]!.choice, "related");
      assert.equal(receipt.advisories[0]!.checkpoint_sha256, PROVENANCE.checkpoint_sha256);
      assert.ok(receipt.artifacts[0]!.note.includes("NOT verified"));
      validateExtensionReceipt(receipt);
      const summary = commitPocReceipt({ sqlitePath: f.path, receipt, store });
      assert.equal(summary.newly_recorded, true);
      assert.equal((await readPocCandidates({ sqlitePath: f.path, payloadRoots: [f.root], intelId: f.item.intel_id })).status, "verified");
      const repeat = commitPocReceipt({ sqlitePath: f.path, receipt: await preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "Open-Jev-2B@0c7aa49", skipAdvisories: true, fetchImpl: (async () => Response.json(jevAnswer(0.97))) as typeof fetch }), store });
      assert.equal(repeat.newly_recorded, false);
      assert.equal(repeat.receipt_id, summary.receipt_id);
    } finally { store.close(); }
  });
});

test("模型不确定/不相关都不得变成 PoC 结论，provenance 不符即拒绝", async () => {
  for (const [name, related, provenance] of [["uncertain", 0.2, PROVENANCE], ["provenance-mismatch", 0.97, { ...PROVENANCE, checkpoint_sha256: "d".repeat(64) }]] as const) {
    await fixture(async f => {
      const store = new SqliteExtensionReceiptStore(f.path);
      try {
        const opts = { sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "Open-Jev-2B@0c7aa49", jevProvenance: provenance, fetchImpl: (async () => Response.json(jevAnswer(related))) as typeof fetch };
        if (name === "provenance-mismatch") {
          await assert.rejects(preparePocReceipt(opts), /provenance/);
          assert.equal(store.get(f.item.intel_id, "poc"), undefined);
        } else {
          const receipt = await preparePocReceipt(opts);
          assert.equal(receipt.advisories[0]!.choice, "unrelated");
          assert.ok(receipt.artifacts.length === 1, "候选仍在，但结论仍只是 advisory");
          assert.equal(receipt.status, "live", "live 只表示存在候选，不表示 PoC 可用");
        }
      } finally { store.close(); }
    });
  }
});

test("原文变更、DQ 撤销、服务不可达都不落成功收据", async () => {
  for (const mutation of ["raw", "dq", "down"] as const) {
    await fixture(async f => {
      const store = new SqliteExtensionReceiptStore(f.path);
      try {
        if (mutation === "raw") {
          await writeFile(f.rawPath, (await (await import("node:fs/promises")).readFile(f.rawPath, "utf8")) + " ");
          await assert.rejects(preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "pinned", fetchImpl: (async () => Response.json(jevAnswer(0.9))) as typeof fetch }), /verified source evidence|changed|missing/);
        } else if (mutation === "dq") {
          const receipt = await preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "pinned", fetchImpl: (async () => Response.json(jevAnswer(0.9))) as typeof fetch });
          commitPocReceipt({ sqlitePath: f.path, receipt, store });
          const entry = readIntelIndexSnapshot(f.path).accepted.get(f.item.intel_id)!;
          await f.bus.publish("dq.verdicts", { ...entry.verdict, verdict: "quarantine" }, { trace_id: "tr_revoke", causation_id: entry.intel_event.event_id });
          assert.equal((await readPocCandidates({ sqlitePath: f.path, payloadRoots: [f.root], intelId: f.item.intel_id })).status, "revoked");
          assert.throws(() => commitPocReceipt({ sqlitePath: f.path, receipt, store }), /Intel.DQ changed/);
        } else {
          await assert.rejects(preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "pinned", fetchImpl: (async () => { throw new Error("ECONNREFUSED"); }) as typeof fetch }), /Open-Jev/);
          assert.equal(store.get(f.item.intel_id, "poc"), undefined);
        }
      } finally { store.close(); }
    });
  }
});

test("KEV 在野利用标记不构成 PoC 候选；无标签引用产 empty 而非假成功", async () => {
  await fixture(async f => {
    const store = new SqliteExtensionReceiptStore(f.path);
    try {
      const receipt = await preparePocReceipt({ sqlitePath: f.path, payloadRoots: [f.root], item: f.item, jevModelId: "pinned", fetchImpl: (async () => Response.json(jevAnswer(0.95))) as typeof fetch });
      const urls = receipt.artifacts.map(a => a.reference_url);
      assert.deepEqual(urls, ["https://example.test/exploit.py"]);
      assert.ok(!urls.some(u => /advisory/.test(u)));
    } finally { store.close(); }
  });
});