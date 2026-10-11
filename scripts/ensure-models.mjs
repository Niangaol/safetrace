#!/usr/bin/env node
/**
 * 本地模型自动就绪（内置下载链接，国内可直连源优先）。
 *
 * 行为（与 docs/TUTORIAL.md §4 一致）：
 *   1. 模型已存在且 sha256 匹配 → 跳过（不重复下载）；
 *   2. 缺失或不匹配 → 依次尝试国内镜像源，成功者写临时文件 + 校验 sha256 后原子替换；
 *   3. 全部源失败或用户拒绝（SAFETRACE_SKIP_MODEL_DOWNLOAD=true）→ 退出码 3，
 *      由调用方（up.ps1 / 服务启动）转走云端 provider，不在本地硬撑。
 *
 * 下载源设计：不放单一源，按「hf-mirror 国内镜像 → huggingface 官方」顺序探测，
 * 谁先返回 200/206 用谁；失败可重跑自动续传（.part 文件删除后重下）。
 *
 * 红线：只写 SAFETRACE_MODELS_DIR（默认 D:\AgentPrograms\safetrace-models），
 * 不动仓库内任何已跟踪文件；sha256 不匹配一律删除重下，不用坏文件。
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, renameSync, unlinkSync } from "node:fs";
import { createReadStream } from "node:fs";
import { join } from "node:path";

/**
 * 下载走 curl 而不是 Node fetch：本机环境下 fetch 拉大文件会被中途 terminate
 * （实测 634MB 只下到 162MB 就断），curl 实测 4.6GB / 86MB-s 稳定。
 * curl 参数：-L 跟随重定向、--retry 自动重试、-C - 断点续传。
 */

/** 模型清单：新增模型只改这里（下载源、体积、sha256 三件套必须齐全）。 */
const MODELS = [
  {
    name: "bge-m3-Q8_0.gguf",
    purpose: "embedding（bge-m3，实测 1024 维）",
    approx_mb: 634,
    sha256: "950f4a8e5e19477a6d3c26d2f162233c20002c601f75e4b002e3239997821167",
    sources: [
      "https://hf-mirror.com/gpustack/bge-m3-GGUF/resolve/main/bge-m3-Q8_0.gguf",
      "https://huggingface.co/gpustack/bge-m3-GGUF/resolve/main/bge-m3-Q8_0.gguf",
    ],
  },
  {
    name: "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    purpose: "chat / Jev 打分底座（Qwen2.5-7B-Instruct Q4_K_M）",
    approx_mb: 4457,
    sha256: "3e357ab3eda2c442f25c0080bb8998eedc05fd16ce1728eacff9ccc5c3d240c6",
    sources: [
      "https://hf-mirror.com/lmstudio-community/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf",
      "https://huggingface.co/lmstudio-community/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf",
    ],
  },
];

const MODELS_DIR = process.env.SAFETRACE_MODELS_DIR ?? "D:\\AgentPrograms\\safetrace-models";
const SKIP = process.env.SAFETRACE_SKIP_MODEL_DOWNLOAD === "true";
const ONLY = process.env.SAFETRACE_MODEL_ONLY ?? "";

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (c) => h.update(c));
    s.on("error", reject);
    s.on("end", () => resolve(h.digest("hex")));
  });
}

async function headOk(url, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: "GET", headers: { range: "bytes=0-0" }, redirect: "follow", signal: ctrl.signal });
    return r.status === 200 || r.status === 206;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function downloadWithCurl(url, dest) {
  const part = dest + ".part";
  // -C - 断点续传；重复调用会接着 .part 往下下，不浪费已传字节
  const args = [
    "-L", "--retry", "3", "--retry-delay", "2", "--connect-timeout", "20",
    "-C", "-", "-o", part, url,
  ];
  const r = spawnSync("curl", args, { stdio: ["ignore", "ignore", "pipe"], encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error("curl 退出码 " + r.status + (r.stderr ? "：" + r.stderr.slice(0, 200) : ""));
  }
  return part;
}

async function download(url, dest, expectSha) {
  const part = downloadWithCurl(url, dest);
  const got = await sha256File(part);
  if (got !== expectSha) {
    unlinkSync(part);
    throw new Error("sha256 不匹配（拿到 " + got.slice(0, 12) + "...，期望 " + expectSha.slice(0, 12) + "...）");
  }
  renameSync(part, dest);
  return true;
}

async function ensureOne(model) {
  const dest = join(MODELS_DIR, model.name);
  if (existsSync(dest)) {
    const got = await sha256File(dest);
    if (got === model.sha256) {
      console.log("[ensure] " + model.name + " 已就绪（sha256 匹配），跳过");
      return "present";
    }
    console.log("[ensure] " + model.name + " 已存在但 sha256 不匹配，将重下");
    unlinkSync(dest);
  }
  if (SKIP) {
    console.log("[ensure] SAFETRACE_SKIP_MODEL_DOWNLOAD=true，跳过 " + model.name + "（调用方应转云端）");
    return "skipped";
  }
  for (const url of model.sources) {
    if (!(await headOk(url))) {
      console.log("[ensure] 源不可用，跳过：" + url);
      continue;
    }
    console.log("[ensure] 下载 " + model.name + "（约 " + model.approx_mb + " MB）← " + url);
    try {
      await download(url, dest, model.sha256);
      console.log("[ensure] " + model.name + " 下载完成并校验通过");
      return "downloaded";
    } catch (err) {
      console.log("[ensure] 该源失败：" + (err instanceof Error ? err.message : String(err)));
    }
  }
  console.log("[ensure] 所有源均失败：" + model.name);
  return "failed";
}

async function main() {
  mkdirSync(MODELS_DIR, { recursive: true });
  const targets = ONLY ? MODELS.filter((m) => m.name.includes(ONLY)) : MODELS;
  let missing = 0;
  for (const m of targets) {
    const r = await ensureOne(m);
    if (r === "failed") missing += 1;
  }
  if (missing > 0) {
    console.log("[ensure] " + missing + " 个模型未就绪；退出码 3，调用方应转云端 provider");
    process.exitCode = 3;
    return;
  }
  console.log("[ensure] 全部模型就绪：" + MODELS_DIR);
}

main().catch((err) => {
  console.error("[ensure] 异常：" + (err instanceof Error ? err.message : String(err)));
  process.exitCode = 3;
});
