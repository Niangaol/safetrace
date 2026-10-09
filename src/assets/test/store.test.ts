import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { AssetsStore } from "../src/store.js";
import type { NewAssetAlert, ScanRun } from "../src/types.js";

const FIXED_NOW = new Date("2026-10-09T08:00:00.000Z");

function makeRun(): ScanRun {
  return {
    run_id: "run-1",
    started_at: "2026-10-09T07:59:50.000Z",
    finished_at: "2026-10-09T08:00:00.000Z",
    roots: ["D:/demo"],
    status: "ok",
    degraded_to: null,
    note: null,
    repo_count: 1,
    component_count: 2,
    repos: [
      {
        repo_id: "repo-1",
        path: "D:/demo/repo",
        remote_url: "https://github.com/demo/repo.git",
        branch: "main",
        head_commit: "abc",
        head_commit_at: "2026-10-01T02:00:00.000Z",
        is_git: true,
        git_note: null,
        languages: ["Node.js"],
        frameworks: ["Vue"],
        manifests: ["package.json"],
        components: [
          { ecosystem: "npm", name: "vue", version: "3.4.21", constraint_raw: "3.4.21", version_is_range_floor: false, source_file: "package.json" },
          { ecosystem: "npm", name: "axios", version: "", constraint_raw: "^1.6.0", version_is_range_floor: true, source_file: "package.json" },
        ],
      },
    ],
    skipped: [],
  };
}

function makeAlert(overrides: Partial<NewAssetAlert> = {}): NewAssetAlert {
  return {
    component_key: "npm:vue",
    ecosystem: "npm",
    name: "vue",
    version: "3.4.21",
    repo_path: "D:/demo/repo",
    cve_id: "CVE-2024-0001",
    intel_id: "intel-1",
    matched_rule: "<3.5.0",
    matched_ranges: ["<3.5.0"],
    reason: "组件版本满足受影响版本规则",
    vendor_unverified: true,
    first_run_id: "run-1",
    ...overrides,
  };
}

test("存储：扫描轮次落库与读取", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.saveScanRun(makeRun(), 0);
    const run = store.latestRun()!;
    assert.equal(run.run_id, "run-1");
    assert.deepEqual(run.roots, ["D:/demo"]);
    const repos = store.listRepos();
    assert.equal(repos.length, 1);
    assert.equal(repos[0]!.component_count, 2);
    assert.deepEqual(repos[0]!.languages, ["Node.js"]);
    const components = store.latestComponents();
    assert.equal(components.length, 2);
    assert.equal(components[0]!.repo_path, "D:/demo/repo");
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("组件查询：生态过滤 + 关键字 + 总数", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.saveScanRun(makeRun(), 0);
    assert.equal(store.listComponents({ ecosystem: "npm" }).total, 2);
    assert.equal(store.listComponents({ ecosystem: "pypi" }).total, 0);
    assert.equal(store.listComponents({ q: "AXIOS" }).total, 1);
    assert.equal(store.listComponents({ q: "demo" }).total, 2, "关键字也匹配仓库路径");
    assert.equal(store.listComponents({ limit: 1 }).rows.length, 1);
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("告警：按 (component_key, cve_id) 去重，重复插入不倍增", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.saveScanRun(makeRun(), 0);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 1);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 0, "同一组件同一 CVE 第二次插入被去重");
    assert.equal(store.insertAlerts([makeAlert({ cve_id: "CVE-2024-0002" })], () => FIXED_NOW), 1);
    assert.equal(store.insertAlerts([makeAlert({ component_key: "npm:axios", name: "axios" })], () => FIXED_NOW), 1);
    assert.equal(store.unreadCount(), 3);
    assert.equal(store.listAlerts({ status: "new" }).length, 3);
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("告警：标记已读（单条与全部），已读后不复活", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.saveScanRun(makeRun(), 0);
    store.insertAlerts([makeAlert(), makeAlert({ cve_id: "CVE-2024-0002" })], () => FIXED_NOW);
    const first = store.listAlerts({ status: "new" })[0]!;
    assert.equal(store.markAlertsRead([first.alert_id], () => FIXED_NOW), 1);
    assert.equal(store.unreadCount(), 1);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 0, "已读告警不因重复匹配复活");
    assert.equal(store.markAlertsRead(undefined, () => FIXED_NOW), 1);
    assert.equal(store.unreadCount(), 0);
    assert.equal(store.listAlerts()[0]!.status, "seen");
    assert.ok(store.listAlerts()[0]!.seen_at !== null);
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("概览：空库返回零值不抛错", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    const overview = store.overview();
    assert.equal(overview.last_run, null);
    assert.equal(overview.unread_count, 0);
    assert.deepEqual(overview.by_ecosystem, {});
    store.saveScanRun(makeRun(), 0);
    store.insertAlerts([makeAlert(), makeAlert({ cve_id: "CVE-2024-0002" })], () => FIXED_NOW);
    const after = store.overview();
    assert.equal(after.repo_count, 1);
    assert.deepEqual(after.by_ecosystem, { npm: 2 });
    assert.equal(after.alert_count, 2);
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
