import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanLocalProjects, type GitRunner } from "../src/scanner.js";

const FIXED_NOW = new Date("2026-10-09T08:00:00.000Z");

async function makeTree(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "safetrace-assets-scan-"));
  // git 仓库 A：根 manifest + monorepo 子包 + 应跳过的 node_modules
  await mkdir(path.join(root, "repo-a", ".git"), { recursive: true });
  await mkdir(path.join(root, "repo-a", "packages", "sub"), { recursive: true });
  await mkdir(path.join(root, "repo-a", "node_modules", "left-pad"), { recursive: true });
  await writeFile(path.join(root, "repo-a", "package.json"), JSON.stringify({ dependencies: { vue: "3.5.0" } }));
  await writeFile(path.join(root, "repo-a", "packages", "sub", "package.json"), JSON.stringify({ dependencies: { react: "18.3.1" } }));
  await writeFile(path.join(root, "repo-a", "node_modules", "left-pad", "package.json"), JSON.stringify({ version: "1.3.0" }));
  // 非 git 项目 B
  await mkdir(path.join(root, "proj-b"), { recursive: true });
  await writeFile(path.join(root, "proj-b", "go.mod"), "module b\ngo 1.22\nrequire github.com/x/y v1.0.0");
  // 普通目录 C（无 manifest）
  await mkdir(path.join(root, "plain-c"), { recursive: true });
  await writeFile(path.join(root, "plain-c", "README.md"), "hi");
  return root;
}

const fakeGit: GitRunner = (args, cwd) => {
  if (args[0] === "remote") return "https://user:token@github.com/demo/repo-a.git\n";
  if (args[0] === "rev-parse") return "main\n";
  if (args[0] === "log") return "abc123\u001f2026-10-01T10:00:00+08:00\n";
  void cwd;
  return null;
};

test("扫描：git 仓库 + 非 git 项目收录，node_modules 跳过，monorepo 子包归入父仓库", async () => {
  const root = await makeTree();
  try {
    const run = await scanLocalProjects({ roots: [root], gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(run.status, "ok");
    assert.equal(run.repo_count, 2);
    const repoA = run.repos.find((r) => r.path.endsWith("repo-a"))!;
    const repoB = run.repos.find((r) => r.path.endsWith("proj-b"))!;
    assert.equal(repoA.is_git, true);
    assert.equal(repoA.remote_url, "https://***@github.com/demo/repo-a.git", "远程地址凭据必须脱敏");
    assert.equal(repoA.branch, "main");
    assert.equal(repoA.head_commit, "abc123");
    assert.equal(repoA.git_note, null);
    const names = repoA.components.map((c) => c.name).sort();
    assert.deepEqual(names, ["react", "vue"], "node_modules 内 manifest 必须被跳过");
    assert.ok(repoA.manifests.includes("packages/sub/package.json"));
    assert.equal(repoB.is_git, false);
    assert.equal(repoB.components[0]!.name, "github.com/x/y");
    assert.ok(run.skipped.length === 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("includeNonGit=false：只收 git 仓库", async () => {
  const root = await makeTree();
  try {
    const run = await scanLocalProjects({ roots: [root], includeNonGit: false, gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(run.repo_count, 1);
    assert.equal(run.repos[0]!.is_git, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("不存在的根目录进 skipped，不抛错", async () => {
  const run = await scanLocalProjects({ roots: [path.join(tmpdir(), "safetrace-no-such-root-xyz")], gitRunner: fakeGit, now: () => FIXED_NOW });
  assert.equal(run.repo_count, 0);
  assert.equal(run.skipped.length, 1);
  assert.match(run.skipped[0]!.reason, /不存在/);
});

test("git 全部不可用：显式降级 git_unavailable，仓库仍收录", async () => {
  const root = await makeTree();
  try {
    const run = await scanLocalProjects({ roots: [root], gitRunner: () => null, now: () => FIXED_NOW });
    assert.equal(run.status, "partial");
    assert.equal(run.degraded_to, "git_unavailable");
    const repoA = run.repos.find((r) => r.path.endsWith("repo-a"))!;
    assert.equal(repoA.remote_url, null);
    assert.equal(repoA.git_note, "git 元信息不可用（remote/branch/HEAD 均读取失败）");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("maxRepos=1：触达仓库上限显式降级 repo_limit", async () => {
  const root = await makeTree();
  try {
    const run = await scanLocalProjects({ roots: [root], maxRepos: 1, gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(run.status, "partial");
    assert.equal(run.degraded_to, "repo_limit");
    assert.equal(run.repo_count, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("分组标识写入 run；缺省 adhoc", async () => {
  const root = await makeTree();
  try {
    const grouped = await scanLocalProjects({ roots: [root], groupId: "g1", groupName: "组一", gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(grouped.group_id, "g1");
    assert.equal(grouped.group_name, "组一");
    const adhoc = await scanLocalProjects({ roots: [root], gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(adhoc.group_id, "adhoc");
    assert.equal(adhoc.group_name, "临时扫描");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("maxDepth=0：只扫根目录自身，不下钻", async () => {
  const root = await makeTree();
  try {
    const run = await scanLocalProjects({ roots: [root], maxDepth: 0, gitRunner: fakeGit, now: () => FIXED_NOW });
    assert.equal(run.repo_count, 0, "根目录自身无 manifest 也无 .git");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
