/**
 * C-06 回归：契约登记一致性。
 * 校验器必须同时保证：schema 目录无未登记文件、CHANGELOG 登记了全部契约、
 * 且有 v1.1.x 增量段。任一不满足都要非零退出。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, copyFileSync, openSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const SCHEMA = join(ROOT, "contracts", "schemas");
const CHANGELOG = join(SCHEMA, "CHANGELOG.md");
const BACKUP = join(ROOT, "tmp", "c06-changelog-backup.md");

function runValidator(): { status: number | null; output: string } {
  mkdirSync(dirname(BACKUP), { recursive: true });
  const fd = openSync(join(ROOT, "tmp", "c06-run.log"), "w");
  const res = spawnSync(process.execPath, [join(ROOT, "scripts", "validate-contracts.mjs")], { cwd: ROOT, stdio: ["ignore", fd, fd] });
  closeSync(fd);
  return { status: res.status, output: readFileSync(join(ROOT, "tmp", "c06-run.log"), "utf8") };
}

function restore(): void {
  copyFileSync(BACKUP, CHANGELOG);
  for (const f of ["c06-run.log"]) rmSync(join(ROOT, "tmp", f), { force: true });
}

let original = "";
test.before(() => {
  mkdirSync(dirname(BACKUP), { recursive: true });
  original = readFileSync(CHANGELOG, "utf8");
  copyFileSync(CHANGELOG, BACKUP);
});
test.after(() => {
  writeFileSync(CHANGELOG, original, "utf8");
  rmSync(BACKUP, { force: true });
  rmSync(join(ROOT, "tmp", "c06-run.log"), { force: true });
});

test("现状：契约登记一致，校验器通过", () => {
  const res = runValidator();
  assert.equal(res.status, 0, res.output);
});

test("CHANGELOG 漏登记契约 → 校验器必须失败", () => {
  writeFileSync(CHANGELOG, original.replace("| RawDoc | Y1/Y2 → Y3 |", "| RawDocX | Y1/Y2 → Y3 |"), "utf8");
  const res = runValidator();
  assert.notEqual(res.status, 0, "漏登记必须被发现");
  assert.match(res.output, /RawDoc\.json/);
  restore();
});

test("schema 目录出现未登记新文件 → 校验器必须失败", () => {
  const stray = join(SCHEMA, "StrayContract.json");
  writeFileSync(stray, JSON.stringify({ $schema: "http://json-schema.org/draft-07/schema#", $id: "x", type: "object" }), "utf8");
  const res = runValidator();
  assert.notEqual(res.status, 0, "未登记文件必须被发现");
  rmSync(stray, { force: true });
  restore();
});

test("缺少 v1.1.x 增量段 → 校验器必须失败", () => {
  writeFileSync(CHANGELOG, original.replace(new RegExp("## v1" + String.raw`\.` + "1" + String.raw`\.` + "[0-9][^" + String.raw`
` + "]*" + String.raw`
`, "g"), ""), "utf8");
  const res = runValidator();
  assert.notEqual(res.status, 0, "缺少增量段必须被发现");
  restore();
});
