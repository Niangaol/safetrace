import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EvidenceChunk, IntelItem } from "@safetrace/shared";
import { SqliteEventStore } from "@safetrace/shared";
import { AssetsStore } from "../../assets/src/store.js";
import type { LiveKnowledgeView } from "../src/live-knowledge-view.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";

/** 私有仓库路径故意用真实形态，用于验证它绝不出现在答案里。 */
const PRIVATE_REPO_PATH = ["D:", "AgentPrograms", "safetrace"].join(String.fromCharCode(92));

const intelItem: IntelItem = {
  intel_id: "intel_log4j",
  cve_ids: ["CVE-2021-44228"],
  source_ids: ["nvd_cve"],
  title: "Apache Log4j2 remote code execution",
  summary: "CVE-2021-44228 Apache Log4j2 JNDI remote code execution.",
  published_at: "2021-12-10T00:00:00.000Z",
  first_seen_at: "2021-12-10T00:00:00.000Z",
  entities: { product: "log4j", vendor: "Apache", version_range: [">=2.0 <2.15.0"], cwe: ["CWE-502"], cpes: [] },
  raw_refs: ["raw_log4j"],
  source_reliability: 0.9,
  schema_version: "1.0",
};

const chunk: EvidenceChunk = {
  chunk_id: "chunk_log4j",
  doc_type: "vuln_advisory",
  text: "CVE-2021-44228 Apache Log4j2 JNDI remote code execution; upgrade log4j to a fixed version.",
  trust: "trusted",
  provenance: { url: "https://example.invalid/log4j", section: "test", sha256: "0".repeat(64) },
};

function fakeView(): LiveKnowledgeView {
  return {
    intel: [intelItem],
    raw: [],
    recorded: new Map(),
    verified: new Map(),
    states: [],
    projection: { fingerprint: "fp_test", watermark: 0, chunks: [chunk], evidence: [] },
  } as unknown as LiveKnowledgeView;
}

async function listen(server: ReturnType<typeof createLiveIntelServer>): Promise<string> {
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return "http://127.0.0.1:" + (server.address() as { port: number }).port;
}
async function close(server: ReturnType<typeof createLiveIntelServer>): Promise<void> {
  await new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
}
function frames(text: string): Array<Record<string, unknown>> {
  return text.split("\n\n").filter(frame => frame.startsWith("data: ")).map(frame => JSON.parse(frame.slice(6)) as Record<string, unknown>);
}
async function ask(url: string, question: string): Promise<{ done: Record<string, unknown>; tokens: string }> {
  const reply = await fetch(url + "/api/v1/qa/chat", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question }) });
  const data = frames(await reply.text());
  const done = data.find(event => event.event === "done");
  assert.ok(done, "chat stream must finish with a done event");
  return { done: done!, tokens: data.filter(event => event.event === "token").map(event => String(event.text)).join("") };
}

/** 建一个只含一轮扫描的资产快照库（npm:log4j@2.14.1，范围约束下界）。 */
async function seedAssets(dbPath: string): Promise<void> {
  const store = new AssetsStore(dbPath);
  try {
    store.upsertGroup({ group_id: "safetrace", name: "SafeTrace 本仓库", roots: ["."], enabled: true, note: null, created_at: "2026-10-01T00:00:00.000Z" });
    store.saveScanRun({
      run_id: "run_seed",
      started_at: "2026-10-09T09:00:00.000Z",
      finished_at: "2026-10-09T09:05:00.000Z",
      group_id: "safetrace",
      group_name: "SafeTrace 本仓库",
      roots: ["."],
      status: "ok",
      degraded_to: null,
      note: null,
      repo_count: 1,
      component_count: 1,
      repos: [{
        repo_id: "repo_seed",
        path: PRIVATE_REPO_PATH,
        remote_url: null,
        branch: "main",
        head_commit: "0".repeat(40),
        head_commit_at: null,
        is_git: true,
        git_note: null,
        languages: ["TypeScript"],
        frameworks: [],
        manifests: ["package.json"],
        components: [{ ecosystem: "npm", name: "log4j", version: "2.14.1", constraint_raw: "^2.14.1", version_is_range_floor: true, source_file: "package.json" }],
      }],
      skipped: [],
    }, 0);
  } finally { store.close(); }
}

test("问答结合本地仓库快照给出三个方向的解决方案，且不泄漏私有路径", async () => {
  const root = await mkdtemp(join(tmpdir(), "safetrace-solution-"));
  const assetsPath = join(root, "assets.sqlite"), intelPath = join(root, "intel.sqlite");
  const store = new SqliteEventStore(intelPath); store.close();
  await seedAssets(assetsPath);
  const server = createLiveIntelServer({ sqlitePath: intelPath, assetsSqlitePath: assetsPath, readView: async () => fakeView() });
  let url = "";
  try {
    url = await listen(server);
    const { done, tokens } = await ask(url, "CVE-2021-44228 如何修复 log4j？");
    assert.equal(done.abstained, false);
    assert.match(tokens, /## 解决方案（基于本地仓库快照）/);
    assert.match(tokens, /### 方案一 · 升级修复/);
    assert.match(tokens, /### 方案二 · 临时缓解/);
    assert.match(tokens, /### 方案三 · 替换或移除/);
    assert.match(tokens, /npm install log4j@<version> --save-exact/);
    assert.match(tokens, /满足受影响版本规则 >=2\.0 <2\.15\.0/);
    assert.match(tokens, /范围约束下界/);
    assert.match(tokens, /1 个分组、1 个组件/);
    assert.ok(!tokens.includes(PRIVATE_REPO_PATH));
    assert.ok(!tokens.includes("AgentPrograms"));
    assert.match(tokens, /仓库指纹 `[0-9a-f]{16}`/);
  } finally { if (url) await close(server); await rm(root, { recursive: true, force: true }); }
});

test("没有可对齐的 CVE/产品时不追加方案段落", async () => {
  const root = await mkdtemp(join(tmpdir(), "safetrace-solution-empty-"));
  const assetsPath = join(root, "assets.sqlite"), intelPath = join(root, "intel.sqlite");
  const store = new SqliteEventStore(intelPath); store.close();
  await seedAssets(assetsPath);
  const server = createLiveIntelServer({ sqlitePath: intelPath, assetsSqlitePath: assetsPath, readView: async () => fakeView() });
  let url = "";
  try {
    url = await listen(server);
    const { tokens } = await ask(url, "什么是零信任架构？");
    assert.ok(!tokens.includes("## 解决方案（基于本地仓库快照）"));
  } finally { if (url) await close(server); await rm(root, { recursive: true, force: true }); }
});

test("快照库缺失或尚未扫描时如实说明，不编组件级方案", async () => {
  const root = await mkdtemp(join(tmpdir(), "safetrace-solution-missing-"));
  const intelPath = join(root, "intel.sqlite");
  const store = new SqliteEventStore(intelPath); store.close();
  const missing = createLiveIntelServer({ sqlitePath: intelPath, assetsSqlitePath: join(root, "absent.sqlite"), readView: async () => fakeView() });
  const unscanned = createLiveIntelServer({ sqlitePath: intelPath, assetsSqlitePath: join(root, "empty.sqlite"), readView: async () => fakeView() });
  const emptyStore = new AssetsStore(join(root, "empty.sqlite")); emptyStore.close();
  let urlMissing = "", urlUnscanned = "";
  try {
    urlMissing = await listen(missing);
    const absent = await ask(urlMissing, "CVE-2021-44228 如何修复 log4j？");
    assert.equal(absent.done.abstained, false);
    assert.match(absent.tokens, /本地资产快照库还不存在/);
    assert.ok(!absent.tokens.includes("### 方案一"));
    urlUnscanned = await listen(unscanned);
    const none = await ask(urlUnscanned, "CVE-2021-44228 如何修复 log4j？");
    assert.match(none.tokens, /本轮无法给出组件级方案/);
    assert.match(none.tokens, /请先在资产页执行扫描/);
    assert.ok(!none.tokens.includes("### 方案一"));
  } finally {
    if (urlMissing) await close(missing);
    if (urlUnscanned) await close(unscanned);
    await rm(root, { recursive: true, force: true });
  }
});
