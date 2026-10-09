import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { AssetsStore } from "../src/store.js";
import type { AssetGroup, NewAssetAlert, ScanRun } from "../src/types.js";

const FIXED_NOW = new Date("2026-10-09T08:00:00.000Z");

function makeGroup(id: string, name: string, roots: string[] = ["D:/demo"]): AssetGroup {
  return { group_id: id, name, roots, enabled: true, note: null, created_at: "2026-10-09T07:00:00.000Z" };
}

function makeRun(groupId = "g1", groupName = "组一"): ScanRun {
  return {
    run_id: "run-1",
    started_at: "2026-10-09T07:59:50.000Z",
    finished_at: "2026-10-09T08:00:00.000Z",
    group_id: groupId,
    group_name: groupName,
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
    group_id: "g1",
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

async function withStore(run: (store: AssetsStore) => void | Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-store-"));
  const store = new AssetsStore(path.join(dir, "assets.sqlite"));
  try {
    await run(store);
  } finally {
    store.close();
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test("分组：增删改查 + 播种只发一次", async () => {
  await withStore((store) => {
    assert.equal(store.seedGroups([makeGroup("g1", "组一"), makeGroup("g2", "组二")]), 2);
    assert.equal(store.seedGroups([makeGroup("g3", "组三")]), 0, "非空库不再播种");
    assert.equal(store.listGroups().length, 2);
    const g1 = store.getGroup("g1")!;
    assert.equal(g1.name, "组一");
    assert.deepEqual(g1.roots, ["D:/demo"]);
    store.upsertGroup({ ...g1, name: "组一改", enabled: false, roots: ["D:/x", "D:/y"] });
    const updated = store.getGroup("g1")!;
    assert.equal(updated.name, "组一改");
    assert.equal(updated.enabled, false);
    assert.deepEqual(updated.roots, ["D:/x", "D:/y"]);
    assert.equal(updated.created_at, g1.created_at, "更新不重置创建时间");
    store.deleteGroup("g2");
    assert.deepEqual(store.listGroups().map((g) => g.group_id), ["g1"]);
  });
});

test("扫描轮次落库与按组读取", async () => {
  await withStore((store) => {
    store.saveScanRun(makeRun("g1", "组一"), 0);
    const run = store.latestRun("g1")!;
    assert.equal(run.run_id, "run-1");
    assert.equal(run.group_id, "g1");
    assert.equal(run.group_name, "组一");
    assert.deepEqual(run.roots, ["D:/demo"]);
    const repos = store.listRepos(undefined, "g1");
    assert.equal(repos.length, 1);
    assert.equal(repos[0]!.group_id, "g1");
    assert.equal(repos[0]!.component_count, 2);
    assert.deepEqual(repos[0]!.languages, ["Node.js"]);
    assert.equal(store.listRepos(undefined, "g2").length, 0, "别的组看不到这轮的仓库");
    const components = store.latestComponents("g1");
    assert.equal(components.length, 2);
    assert.equal(components[0]!.repo_path, "D:/demo/repo");
    assert.equal(components[0]!.group_id, "g1");
  });
});

test("分组隔离：两组各自最新快照，互不污染", async () => {
  await withStore((store) => {
    store.saveScanRun(makeRun("g1", "组一"), 0);
    const run2 = makeRun("g2", "组二");
    run2.run_id = "run-2";
    run2.finished_at = "2026-10-09T09:00:00.000Z";
    run2.repos[0]!.repo_id = "repo-2";
    run2.repos[0]!.path = "D:/other/repo";
    store.saveScanRun(run2, 0);
    assert.equal(store.latestRun("g1")!.run_id, "run-1");
    assert.equal(store.latestRun("g2")!.run_id, "run-2");
    assert.equal(store.latestRun()!.run_id, "run-2", "全局最近 = 完成时间最晚");
    assert.equal(store.latestComponents("g1").length, 2);
    assert.equal(store.latestComponents("g2").length, 2);
    assert.equal(store.latestComponents().length, 4, "缺组 = 所有分组最新快照");
    assert.equal(store.listRepos(undefined, "g2")[0]!.path, "D:/other/repo");
  });
});

test("组件查询：分组 + 生态过滤 + 关键字 + 总数", async () => {
  await withStore((store) => {
    store.saveScanRun(makeRun("g1", "组一"), 0);
    assert.equal(store.listComponents({ groupId: "g1", ecosystem: "npm" }).total, 2);
    assert.equal(store.listComponents({ groupId: "g1", ecosystem: "pypi" }).total, 0);
    assert.equal(store.listComponents({ groupId: "g1", q: "AXIOS" }).total, 1);
    assert.equal(store.listComponents({ groupId: "g1", q: "demo" }).total, 2, "关键字也匹配仓库路径");
    assert.equal(store.listComponents({ groupId: "g1", limit: 1 }).rows.length, 1);
    assert.equal(store.listComponents({ groupId: "g2" }).total, 0);
  });
});

test("告警：同组同 CVE 去重；不同组同 CVE 各提醒一次", async () => {
  await withStore((store) => {
    store.saveScanRun(makeRun("g1", "组一"), 0);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 1);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 0, "同组同 CVE 第二次插入被去重");
    assert.equal(store.insertAlerts([makeAlert({ cve_id: "CVE-2024-0002" })], () => FIXED_NOW), 1);
    assert.equal(store.insertAlerts([makeAlert({ group_id: "g2" })], () => FIXED_NOW), 1, "不同组同 CVE 各自提醒");
    assert.equal(store.unreadCount(), 3);
    assert.equal(store.unreadCount("g1"), 2);
    assert.equal(store.unreadCount("g2"), 1);
    assert.equal(store.listAlerts({ groupId: "g1", status: "new" }).length, 2);
    assert.equal(store.listAlerts({ status: "new" }).length, 3);
  });
});

test("告警：标记已读（单条/按组/全部），已读后不复活", async () => {
  await withStore((store) => {
    store.saveScanRun(makeRun("g1", "组一"), 0);
    store.insertAlerts([makeAlert(), makeAlert({ cve_id: "CVE-2024-0002" }), makeAlert({ group_id: "g2" })], () => FIXED_NOW);
    const first = store.listAlerts({ groupId: "g1", status: "new" })[0]!;
    assert.equal(store.markAlertsRead([first.alert_id], undefined, () => FIXED_NOW), 1);
    assert.equal(store.unreadCount("g1"), 1);
    assert.equal(store.insertAlerts([makeAlert()], () => FIXED_NOW), 0, "已读告警不因重复匹配复活");
    assert.equal(store.markAlertsRead(undefined, "g1", () => FIXED_NOW), 1, "按组全部已读只动该组");
    assert.equal(store.unreadCount("g1"), 0);
    assert.equal(store.unreadCount("g2"), 1);
    assert.equal(store.markAlertsRead(undefined, undefined, () => FIXED_NOW), 1);
    assert.equal(store.unreadCount(), 0);
    assert.ok(store.listAlerts()[0]!.seen_at !== null);
  });
});

test("概览：空库零值；分组聚合与 by_group", async () => {
  await withStore((store) => {
    const empty = store.overview();
    assert.equal(empty.last_run, null);
    assert.equal(empty.unread_count, 0);
    assert.deepEqual(empty.by_ecosystem, {});
    assert.deepEqual(empty.by_group, []);

    store.saveScanRun(makeRun("g1", "组一"), 0);
    store.insertAlerts([makeAlert(), makeAlert({ cve_id: "CVE-2024-0002" })], () => FIXED_NOW);
    const after = store.overview("g1");
    assert.equal(after.group_id, "g1");
    assert.equal(after.group_name, "组一");
    assert.equal(after.repo_count, 1);
    assert.deepEqual(after.by_ecosystem, { npm: 2 });
    assert.equal(after.alert_count, 2);
    assert.equal(after.unread_count, 2);
    assert.equal(after.by_group.length, 1);

    const run2 = makeRun("g2", "组二");
    run2.run_id = "run-2";
    run2.finished_at = "2026-10-09T09:00:00.000Z";
    store.saveScanRun(run2, 0);
    const all = store.overview();
    assert.equal(all.group_id, null);
    assert.equal(all.repo_count, 2, "全部组聚合 = 各组最新一轮之和");
    assert.equal(all.component_count, 4);
    assert.deepEqual(all.by_ecosystem, { npm: 4 });
    assert.equal(all.by_group.length, 2);
  });
});

test("分组统计：listGroupsWithStats 汇总未读与最近扫描", async () => {
  await withStore((store) => {
    store.seedGroups([makeGroup("g1", "组一"), makeGroup("g2", "组二")]);
    store.saveScanRun(makeRun("g1", "组一"), 0);
    store.insertAlerts([makeAlert()], () => FIXED_NOW);
    const stats = store.listGroupsWithStats();
    const g1 = stats.find((s) => s.group_id === "g1")!;
    const g2 = stats.find((s) => s.group_id === "g2")!;
    assert.equal(g1.repo_count, 1);
    assert.equal(g1.unread_count, 1);
    assert.equal(g1.last_finished_at, "2026-10-09T08:00:00.000Z");
    assert.equal(g2.repo_count, 0);
    assert.equal(g2.last_finished_at, null, "没扫过的组最近时间为空");
  });
});
