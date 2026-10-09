/**
 * 扫描配置解析：config/assets-scan.json（仓库内，可入库）→ 环境变量 → 默认值。
 *
 * 分组模型（v2，2026-10-09）：
 *   { "groups": [ { "id", "name", "roots": [...], "enabled", "note" } ], "limits": {...}, "skipDirNames": [...] }
 * - roots 支持相对路径（相对仓库根）与绝对路径；
 * - 兼容旧平铺格式 { "roots": [...] }：自动包装为单个 "default" 分组；
 * - 完全没有配置时播种两个默认组：SafeTrace 本仓库 + 上一级目录（本机项目群）。
 *
 * 分组的运行时真相源是 var/assets.sqlite 的 groups 表（UI 可增删改）；
 * 配置文件只在 groups 表为空时播种一次。
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { DEFAULT_SCAN_LIMITS, type ScanOptions } from "./scanner.js";
import type { AssetGroup } from "./types.js";

export interface ScanGroupConfig {
  id: string;
  name: string;
  roots: string[];
  enabled?: boolean;
  note?: string;
}

export interface ScanConfig {
  groups: ScanGroupConfig[];
  limits: Partial<typeof DEFAULT_SCAN_LIMITS>;
  skipDirNames: string[];
}

interface ScanConfigFile {
  groups?: unknown;
  roots?: unknown;
  limits?: Record<string, unknown>;
  skipDirNames?: unknown;
}

const GROUP_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/;

/** 默认分组：本仓库 + 上一级目录（本机项目聚集地）。 */
function defaultGroups(): ScanGroupConfig[] {
  return [
    { id: "safetrace", name: "SafeTrace 本仓库", roots: ["."], enabled: true, note: "竞赛主工程" },
    { id: "agentprograms", name: "AgentPrograms 项目群", roots: [".."], enabled: true, note: "本机其他项目" },
  ];
}

function parseGroups(raw: unknown): ScanGroupConfig[] | null {
  if (!Array.isArray(raw)) return null;
  const out: ScanGroupConfig[] = [];
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue;
    const rec = entry as Record<string, unknown>;
    const id = typeof rec.id === "string" ? rec.id.trim() : "";
    const name = typeof rec.name === "string" ? rec.name.trim() : "";
    const roots = Array.isArray(rec.roots) ? rec.roots.filter((r): r is string => typeof r === "string" && r.trim() !== "") : [];
    if (!GROUP_ID_PATTERN.test(id) || name === "" || roots.length === 0) continue;
    out.push({
      id,
      name,
      roots,
      enabled: rec.enabled === undefined ? true : Boolean(rec.enabled),
      ...(typeof rec.note === "string" ? { note: rec.note } : {}),
    });
  }
  return out.length > 0 ? out : null;
}

/** 从仓库根解析扫描配置；cwd 一般是 SafeTrace 仓库根。 */
export function resolveScanConfig(cwd: string = process.cwd()): ScanConfig {
  const configPath = path.join(cwd, "config", "assets-scan.json");
  let file: ScanConfigFile = {};
  if (existsSync(configPath)) {
    try {
      file = JSON.parse(readFileSync(configPath, "utf8")) as ScanConfigFile;
    } catch {
      file = {}; // 坏配置按默认走，但调用方应能从 roots 看出没读到你写的值
    }
  }

  let groups = parseGroups(file.groups);
  if (groups === null && Array.isArray(file.roots) && file.roots.every((r) => typeof r === "string") && file.roots.length > 0) {
    // 旧平铺格式：包装成单个默认组（向后兼容）
    groups = [{ id: "default", name: "默认分组（旧配置迁移）", roots: file.roots as string[], enabled: true }];
  }
  if (groups === null && process.env.SAFETRACE_SCAN_ROOTS) {
    const roots = process.env.SAFETRACE_SCAN_ROOTS.split(path.delimiter).map((r) => r.trim()).filter(Boolean);
    if (roots.length > 0) groups = [{ id: "env", name: "环境变量分组", roots, enabled: true }];
  }
  if (groups === null) groups = defaultGroups();

  const limits: Partial<typeof DEFAULT_SCAN_LIMITS> = {};
  const fileLimits = file.limits ?? {};
  for (const key of Object.keys(DEFAULT_SCAN_LIMITS) as Array<keyof typeof DEFAULT_SCAN_LIMITS>) {
    const value = fileLimits[key];
    if (typeof value === "number" && Number.isFinite(value) && value > 0) {
      (limits as Record<string, number>)[key] = value;
    }
  }

  const skipDirNames = Array.isArray(file.skipDirNames) ? file.skipDirNames.filter((n): n is string => typeof n === "string") : [];
  return { groups, limits, skipDirNames };
}

/** 配置分组 → 存储用 AssetGroup（roots 解析为绝对路径）。 */
export function groupsFromConfig(cwd: string = process.cwd()): AssetGroup[] {
  const config = resolveScanConfig(cwd);
  const now = new Date().toISOString();
  return config.groups.map((group) => ({
    group_id: group.id,
    name: group.name,
    roots: group.roots.map((r) => path.resolve(cwd, r)),
    enabled: group.enabled !== false,
    note: group.note ?? null,
    created_at: now,
  }));
}

/** 单个分组的扫描参数。 */
export function scanOptionsForGroup(cwd: string, group: AssetGroup): ScanOptions {
  const config = resolveScanConfig(cwd);
  return {
    roots: group.roots,
    groupId: group.group_id,
    groupName: group.name,
    ...config.limits,
    ...(config.skipDirNames.length > 0 ? { skipDirNames: config.skipDirNames } : {}),
  };
}

/** 资产库默认路径：var/assets.sqlite（*.sqlite 已被 .gitignore 覆盖）。 */
export function defaultAssetsDbPath(cwd: string = process.cwd()): string {
  return path.resolve(cwd, "var", "assets.sqlite");
}
