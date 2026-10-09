/**
 * 本地项目扫描器：发现 git 仓库/项目目录 → 解析 manifest → 产出技术栈快照。
 *
 * 红线（与项目合规一致）：
 * - 只读本地文件与 git 本地元信息，零网络探测；
 * - 一切限制（深度/数量/大小/超时）命中都显式记录，不静默截断；
 * - git 不可用是显式降级（degraded_to=git_unavailable），不是静默跳过。
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { nextId } from "@safetrace/shared";
import { parseManifest } from "./manifests.js";
import type { Component, RepoSnapshot, ScanRun, ScanSkip } from "./types.js";

export type GitRunner = (args: string[], cwd: string) => string | null;

export interface ScanOptions {
  roots: string[];
  /** 本轮扫描所属分组；缺省 "adhoc"（一次性扫描）。 */
  groupId?: string;
  /** 分组展示名；缺省 "临时扫描"。 */
  groupName?: string;
  /** 相对扫描根的目录遍历深度，默认 6。 */
  maxDepth?: number;
  maxRepos?: number;
  maxReposPerRoot?: number;
  maxComponents?: number;
  /** manifest 收集深度（相对扫描根），默认 5。 */
  manifestDepth?: number;
  maxManifestFilesPerRepo?: number;
  maxManifestBytes?: number;
  /** 非 git 目录含 manifest 时也按项目收录，默认 true。 */
  includeNonGit?: boolean;
  skipDirNames?: readonly string[];
  /** 追加的目录名正则（source 形式），如 "^pythoncore-"、"site-packages$"。 */
  skipDirPatterns?: readonly string[];
  timeoutMs?: number;
  /** 测试注入用；默认走本机 git（仅本地只读子命令）。 */
  gitRunner?: GitRunner;
  now?: () => Date;
}

export const DEFAULT_SCAN_LIMITS = {
  maxDepth: 6,
  maxRepos: 400,
  maxReposPerRoot: 100,
  maxComponents: 5000,
  manifestDepth: 5,
  maxManifestFilesPerRepo: 60,
  maxManifestBytes: 1_048_576,
  timeoutMs: 120_000,
} as const;

/** 默认跳过的目录名：依赖目录、构建产物、运行时与系统目录。 */
export const DEFAULT_SKIP_DIR_NAMES: readonly string[] = [
  "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", ".output",
  "__pycache__", ".venv", "venv", "env", ".cache", ".tmp", "tmp", "temp",
  "site-packages", "qdrant-storage", ".qdrant-storage", "coverage", ".idea", ".vscode",
  "target", "bin", "obj", ".gradle", ".mvn", "vendor",
  "$recycle.bin", "system volume information", "recovery", "windows",
  "program files", "program files (x86)", "programdata", "appdata",
  "deliverables", "snapshots", ".models", "models",
];

/** 默认跳过的目录名正则（大小写不敏感）。 */
export const DEFAULT_SKIP_DIR_PATTERNS: readonly string[] = ["^pythoncore-", "site-packages$"];

const KNOWN_MANIFEST_NAMES = new Set([
  "package.json", "requirements.txt", "pyproject.toml", "pipfile",
  "go.mod", "cargo.toml", "pom.xml", "composer.json", "gemfile",
  "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
]);

function isKnownManifest(name: string): boolean {
  return KNOWN_MANIFEST_NAMES.has(name.toLowerCase());
}

/** 仓库内收集 manifest 时同样要跳过的目录（与遍历跳过名单对齐的子集）。 */
const MANIFEST_SKIP_DIRS = new Set([
  ".git", "node_modules", "__pycache__", ".venv", "venv", "env", "site-packages",
  "dist", "build", "out", "target", "vendor", "coverage", ".next", ".nuxt", ".cache",
]);

function shouldSkipManifestDir(name: string): boolean {
  return MANIFEST_SKIP_DIRS.has(name.toLowerCase()) || /^pythoncore-/i.test(name);
}

/** 默认 git 执行器：只跑本地只读子命令，5s 超时；git 缺失/非零退出都返回 null。 */
export function defaultGitRunner(timeoutMs = 5000): GitRunner {
  return (args, cwd) => {
    const result = spawnSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      timeout: timeoutMs,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) return null;
    return result.stdout;
  };
}

/** 脱敏远程地址里的凭据（https://user:token@host/... → //***@host/...）。 */
function redactRemote(url: string): string {
  return url.replace(/\/\/[^/@\/]+@/, "//***@");
}

interface WalkDir {
  dir: string;
  depth: number;
  insideRepo: boolean;
}

export async function scanLocalProjects(options: ScanOptions): Promise<ScanRun> {
  const limits = { ...DEFAULT_SCAN_LIMITS, ...stripUndefined(options) };
  const skipNames = new Set([...DEFAULT_SKIP_DIR_NAMES, ...(options.skipDirNames ?? [])].map((n) => n.toLowerCase()));
  const skipPatterns = [...DEFAULT_SKIP_DIR_PATTERNS, ...(options.skipDirPatterns ?? [])].map((p) => new RegExp(p, "i"));
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const deadline = Date.now() + limits.timeoutMs;

  let gitCalls = 0;
  let gitFailures = 0;
  const providedGit = options.gitRunner;
  const git: GitRunner = (args, cwd) => {
    gitCalls += 1;
    const out = providedGit ? providedGit(args, cwd) : defaultGitRunner()(args, cwd);
    if (out === null) gitFailures += 1;
    return out;
  };

  const repos: RepoSnapshot[] = [];
  const skipped: ScanSkip[] = [];
  let degraded: string | null = null;
  let note: string | null = null;
  let totalComponents = 0;

  const markDegraded = (code: string, extra?: string): void => {
    if (degraded === null) degraded = code;
    if (extra) note = note ? note + "；" + extra : extra;
  };

  for (const rawRoot of options.roots) {
    const root = path.resolve(rawRoot);
    let rootIsDir = false;
    try {
      rootIsDir = (await stat(root)).isDirectory();
    } catch {
      rootIsDir = false;
    }
    if (!rootIsDir) {
      skipped.push({ path: root, reason: "扫描根不存在或不是目录" });
      continue;
    }
    let reposInRoot = 0;
    const stack: WalkDir[] = [{ dir: root, depth: 0, insideRepo: false }];

    while (stack.length > 0) {
      if (Date.now() > deadline) {
        markDegraded("timeout", "扫描超时（" + limits.timeoutMs + "ms），结果不完整");
        break;
      }
      if (repos.length >= limits.maxRepos) {
        markDegraded("repo_limit", "仓库数达到上限 " + limits.maxRepos);
        break;
      }
      const current = stack.pop()!;
      let entries;
      try {
        entries = await readdir(current.dir, { withFileTypes: true });
      } catch (error) {
        skipped.push({ path: current.dir, reason: "目录不可读：" + (error instanceof Error ? error.message : String(error)) });
        markDegraded("read_error");
        continue;
      }

      const hasGit = entries.some((e) => e.name === ".git");
      let insideRepo = current.insideRepo;
      if (hasGit && !insideRepo) {
        if (reposInRoot >= limits.maxReposPerRoot) {
          skipped.push({ path: current.dir, reason: "单根仓库数超限" });
        } else {
          const repo = await readRepo(current.dir, true, git);
          const manifests = await collectManifests(current.dir, current.dir, limits, skipped);
          await loadRepoComponents(repo, manifests, limits.maxManifestBytes);
          repos.push(repo);
          reposInRoot += 1;
          totalComponents += repo.components.length;
          insideRepo = true;
        }
      } else if (!insideRepo && options.includeNonGit !== false && entries.some((e) => e.isFile() && isKnownManifest(e.name))) {
        if (reposInRoot >= limits.maxReposPerRoot) {
          skipped.push({ path: current.dir, reason: "单根仓库数超限" });
        } else {
          const repo = await readRepo(current.dir, false, git);
          const manifests = await collectManifests(current.dir, current.dir, limits, skipped);
          await loadRepoComponents(repo, manifests, limits.maxManifestBytes);
          repos.push(repo);
          reposInRoot += 1;
          totalComponents += repo.components.length;
          insideRepo = true;
        }
      }

      if (totalComponents >= limits.maxComponents) {
        markDegraded("component_limit", "组件数达到上限 " + limits.maxComponents);
        break;
      }

      if (current.depth >= limits.maxDepth) continue;
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const lower = entry.name.toLowerCase();
        if (skipNames.has(lower)) continue;
        if (skipPatterns.some((p) => p.test(entry.name))) continue;
        stack.push({ dir: path.join(current.dir, entry.name), depth: current.depth + 1, insideRepo });
      }
    }
  }

  if (gitCalls > 0 && gitFailures === gitCalls) {
    markDegraded("git_unavailable", "git 元信息全部读取失败（git 未安装或不在 PATH）");
  }

  const finishedAt = now();
  return {
    run_id: nextId("run"),
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    group_id: options.groupId ?? "adhoc",
    group_name: options.groupName ?? "临时扫描",
    roots: options.roots.map((r) => path.resolve(r)),
    status: degraded === null ? "ok" : "partial",
    degraded_to: degraded,
    note,
    repo_count: repos.length,
    component_count: repos.reduce((sum, r) => sum + r.components.length, 0),
    repos,
    skipped,
  };
}

function stripUndefined(options: ScanOptions): Partial<typeof DEFAULT_SCAN_LIMITS> {
  const out: Record<string, number> = {};
  const keys = ["maxDepth", "maxRepos", "maxReposPerRoot", "maxComponents", "manifestDepth", "maxManifestFilesPerRepo", "maxManifestBytes", "timeoutMs"] as const;
  for (const key of keys) {
    const value = options[key];
    const allowsZero = key === "maxDepth" || key === "manifestDepth";
    if (typeof value === "number" && Number.isFinite(value) && (value > 0 || (allowsZero && value === 0))) out[key] = value;
  }
  return out as Partial<typeof DEFAULT_SCAN_LIMITS>;
}

async function readRepo(dir: string, isGit: boolean, git: GitRunner): Promise<RepoSnapshot> {
  let remote_url: string | null = null;
  let branch: string | null = null;
  let head_commit: string | null = null;
  let head_commit_at: string | null = null;
  let git_note: string | null = null;

  if (isGit) {
    const remoteOut = git(["remote", "get-url", "origin"], dir);
    if (remoteOut !== null && remoteOut.trim()) remote_url = redactRemote(remoteOut.trim());
    const branchOut = git(["rev-parse", "--abbrev-ref", "HEAD"], dir);
    if (branchOut !== null && branchOut.trim()) branch = branchOut.trim();
    const headOut = git(["log", "-1", "--format=%H%x1f%cI"], dir);
    if (headOut !== null && headOut.trim()) {
      const parts = headOut.trim().split("\u001f");
      head_commit = parts[0] || null;
      head_commit_at = parts[1] || null;
    }
    if (remote_url === null && branch === null && head_commit === null) {
      git_note = "git 元信息不可用（remote/branch/HEAD 均读取失败）";
    } else if (remote_url === null) {
      git_note = "未配置 origin 远程";
    }
  }

  return {
    repo_id: nextId("repo"),
    path: dir,
    remote_url,
    branch,
    head_commit,
    head_commit_at,
    is_git: isGit,
    git_note,
    languages: [],
    frameworks: [],
    manifests: [],
    components: [],
  };
}

interface CollectedManifest {
  rel: string;
  abs: string;
}

/** 在 repo 根向下收集 manifest 文件（受 manifestDepth 限制，相对扫描根计算由调用方控制）。 */
async function collectManifests(
  repoRoot: string,
  scanRoot: string,
  limits: typeof DEFAULT_SCAN_LIMITS,
  skipped: ScanSkip[],
): Promise<CollectedManifest[]> {
  const out: CollectedManifest[] = [];
  const baseDepth = repoRoot === scanRoot ? 0 : path.relative(scanRoot, repoRoot).split(path.sep).length;
  const stack: Array<{ dir: string; depth: number }> = [{ dir: repoRoot, depth: baseDepth }];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.depth > limits.manifestDepth) continue;
    let entries;
    try {
      entries = await readdir(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        const isWorkflow = current.dir.replaceAll("\\", "/").includes(".github/workflows/") && (lower.endsWith(".yml") || lower.endsWith(".yaml"));
        if (!isKnownManifest(lower) && !isWorkflow) continue;
        if (out.length >= limits.maxManifestFilesPerRepo) {
          skipped.push({ path: path.join(current.dir, entry.name), reason: "仓库 manifest 数超限（" + limits.maxManifestFilesPerRepo + "）" });
          return out;
        }
        out.push({ rel: path.relative(repoRoot, path.join(current.dir, entry.name)).replaceAll("\\", "/"), abs: path.join(current.dir, entry.name) });
      } else if (entry.isDirectory()) {
        if (shouldSkipManifestDir(entry.name)) continue;
        stack.push({ dir: path.join(current.dir, entry.name), depth: current.depth + 1 });
      }
    }
  }
  return out;
}

/** 读取并解析 manifest 内容（大小受 maxManifestBytes 限制），合并进 repo。 */
export async function loadRepoComponents(repo: RepoSnapshot, manifests: CollectedManifest[], maxBytes: number): Promise<void> {
  for (const m of manifests) {
    let size = 0;
    try {
      size = (await stat(m.abs)).size;
    } catch {
      continue;
    }
    if (size > maxBytes) continue;
    let content: string;
    try {
      content = await readFile(m.abs, "utf8");
    } catch {
      continue;
    }
    const parsed = parseManifest(m.rel, content);
    repo.manifests.push(m.rel);
    for (const c of parsed.components) repo.components.push(c);
    for (const l of parsed.languages) if (!repo.languages.includes(l)) repo.languages.push(l);
    for (const f of parsed.frameworks) if (!repo.frameworks.includes(f)) repo.frameworks.push(f);
  }
}
