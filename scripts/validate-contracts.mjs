#!/usr/bin/env node
/**
 * 契约校验跨平台入口（npm run validate:contracts 与 .githooks/pre-push 共用同一实现）。
 *
 * 为什么不是一行 bash：Windows 上 npm 用 cmd.exe 执行 package.json 脚本，
 * `command -v` 不存在，`PY=$(command -v python3 || command -v python) && "$PY" ...`
 * 必然失败——PR #1 曾因此宣称"本地门禁首次 exit 0"而实际 exit 1（假绿）。
 * 且 Git bash 里 `command -v python3` 可能命中 Microsoft Store 占位别名
 * （找得到、未必跑得了）。本文件三条保证：
 *   1. 按序探测 SAFETRACE_PYTHON -> python3 -> python -> py，每个候选"真跑 --version"验证；
 *   2. 校验脚本的退出码原样透传，失败就是失败，不粉饰；
 *   3. 一个可用解释器都没有时显式 exit 1 并说清原因，绝不静默跳过。
 *
 * 用法：node scripts/validate-contracts.mjs
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SCRIPT = join(ROOT, "scripts", "validate_contracts.py");

/** 真跑一次 --version：找得到还不够，必须能跑（防 Store 占位别名）。 */
function usable(bin) {
  const probe = spawnSync(bin, ["--version"], { stdio: "ignore" });
  return !probe.error && probe.status === 0;
}

function runWith(bin) {
  const res = spawnSync(bin, [SCRIPT], { stdio: "inherit" });
  if (res.error) {
    console.error(`[validate-contracts] 启动 ${bin} 失败：${res.error.message}`);
    process.exit(1);
  }
  process.exit(res.status ?? 1);
}

if (process.env.SAFETRACE_PYTHON) {
  // 显式指定优先：设了就必须可用，不悄悄换解释器（意图明确时不打折扣）
  if (!usable(process.env.SAFETRACE_PYTHON)) {
    console.error(`[validate-contracts] SAFETRACE_PYTHON 指定的解释器不可用：${process.env.SAFETRACE_PYTHON}`);
    process.exit(1);
  }
  runWith(process.env.SAFETRACE_PYTHON);
} else {
  const found = ["python3", "python", "py"].find(usable);
  if (!found) {
    console.error("[validate-contracts] 本机探测不到可用的 Python 解释器（python3 / python / py 均不可用）。");
    console.error("  处理：装一个 Python 3，或用环境变量 SAFETRACE_PYTHON 指定解释器路径。");
    console.error("  契约校验是合并前门禁，不允许跳过。");
    process.exit(1);
  }
  runWith(found);
}
