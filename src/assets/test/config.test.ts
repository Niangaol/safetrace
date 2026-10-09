import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { resolveScanConfig, groupsFromConfig, scanOptionsForGroup, defaultAssetsDbPath } from "../src/config.js";

async function withCwd(config: unknown, run: (cwd: string) => void | Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-config-"));
  try {
    await mkdir(path.join(dir, "config"), { recursive: true });
    if (config !== undefined) {
      await writeFile(path.join(dir, "config", "assets-scan.json"), typeof config === "string" ? config : JSON.stringify(config), "utf8");
    }
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test("配置：groups 新格式解析 + limits + skipDirNames", async () => {
  const prev = process.env.SAFETRACE_SCAN_ROOTS;
  delete process.env.SAFETRACE_SCAN_ROOTS;
  await withCwd({
    groups: [
      { id: "g1", name: "组一", roots: [".", "../other"], enabled: false, note: "备注" },
      { id: "g2", name: "组二", roots: ["D:/abs"] },
      { id: "bad id", name: "非法 id 跳过", roots: ["."] },
      { id: "g3", name: "空 roots 跳过", roots: [] },
      "not-an-object",
    ],
    limits: { maxDepth: 3, timeoutMs: -5 },
    skipDirNames: ["myvendor"],
  }, (cwd) => {
    const config = resolveScanConfig(cwd);
    assert.equal(config.groups.length, 2);
    assert.equal(config.groups[0]!.id, "g1");
    assert.equal(config.groups[0]!.enabled, false);
    assert.equal(config.groups[0]!.note, "备注");
    assert.equal(config.groups[1]!.enabled, true, "enabled 缺省 true");
    assert.equal(config.limits.maxDepth, 3);
    assert.equal(config.limits.timeoutMs, undefined, "非法 limit 忽略");
    assert.deepEqual(config.skipDirNames, ["myvendor"]);
    const groups = groupsFromConfig(cwd);
    assert.deepEqual(groups[0]!.roots, [path.resolve(cwd, "."), path.resolve(cwd, "../other")], "相对 roots 解析为绝对路径");
    assert.deepEqual(groups[1]!.roots, [path.resolve("D:/abs")], "绝对 roots 经 resolve 规范化");
    const options = scanOptionsForGroup(cwd, groups[0]!);
    assert.equal(options.groupId, "g1");
    assert.equal(options.groupName, "组一");
    assert.equal(options.maxDepth, 3);
    assert.equal(defaultAssetsDbPath(cwd), path.resolve(cwd, "var", "assets.sqlite"));
  });
  if (prev !== undefined) process.env.SAFETRACE_SCAN_ROOTS = prev;
});

test("配置：旧平铺 roots 兼容为单个 default 组", async () => {
  const prev = process.env.SAFETRACE_SCAN_ROOTS;
  delete process.env.SAFETRACE_SCAN_ROOTS;
  await withCwd({ roots: [".", ".."], limits: { maxDepth: 4 } }, (cwd) => {
    const config = resolveScanConfig(cwd);
    assert.equal(config.groups.length, 1);
    assert.equal(config.groups[0]!.id, "default");
    assert.deepEqual(config.groups[0]!.roots, [".", ".."]);
    assert.equal(config.limits.maxDepth, 4);
  });
  if (prev !== undefined) process.env.SAFETRACE_SCAN_ROOTS = prev;
});

test("配置：无配置文件时播种两个默认组", async () => {
  const prev = process.env.SAFETRACE_SCAN_ROOTS;
  delete process.env.SAFETRACE_SCAN_ROOTS;
  await withCwd(undefined, (cwd) => {
    const config = resolveScanConfig(cwd);
    assert.deepEqual(config.groups.map((g) => g.id), ["safetrace", "agentprograms"]);
    assert.deepEqual(config.groups[0]!.roots, ["."]);
    assert.deepEqual(config.groups[1]!.roots, [".."]);
  });
  if (prev !== undefined) process.env.SAFETRACE_SCAN_ROOTS = prev;
});

test("配置：坏 JSON 按默认走；环境变量在无配置时生效", async () => {
  const prev = process.env.SAFETRACE_SCAN_ROOTS;
  delete process.env.SAFETRACE_SCAN_ROOTS;
  await withCwd("{ not json", (cwd) => {
    const config = resolveScanConfig(cwd);
    assert.deepEqual(config.groups.map((g) => g.id), ["safetrace", "agentprograms"]);
  });
  await withCwd(undefined, (cwd) => {
    process.env.SAFETRACE_SCAN_ROOTS = ["D:/a", "D:/b"].join(path.delimiter);
    const config = resolveScanConfig(cwd);
    assert.equal(config.groups.length, 1);
    assert.equal(config.groups[0]!.id, "env");
    assert.deepEqual(config.groups[0]!.roots, ["D:/a", "D:/b"]);
    delete process.env.SAFETRACE_SCAN_ROOTS;
  });
  if (prev !== undefined) process.env.SAFETRACE_SCAN_ROOTS = prev;
});
