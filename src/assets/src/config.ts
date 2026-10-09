/**
 * 扫描配置解析：config/assets-scan.json（仓库内，可入库）→ 环境变量 → 默认值。
 *
 * roots 支持相对路径（相对仓库根目录，即本配置文件所在仓库的根）与绝对路径。
 * 默认值：仓库自身 + 上一级目录（本机项目聚集地），两者不存在时自动跳过并留痕。
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { DEFAULT_SCAN_LIMITS, type ScanOptions } from "./scanner.js";

export interface ScanConfig {
  roots: string[];
  limits: Partial<typeof DEFAULT_SCAN_LIMITS>;
  skipDirNames: string[];
}

interface ScanConfigFile {
  roots?: unknown;
  limits?: Record<string, unknown>;
  skipDirNames?: unknown;
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

  let roots: string[];
  if (Array.isArray(file.roots) && file.roots.every((r) => typeof r === "string")) {
    roots = (file.roots as string[]).map((r) => path.resolve(cwd, r));
  } else if (process.env.SAFETRACE_SCAN_ROOTS) {
    roots = process.env.SAFETRACE_SCAN_ROOTS.split(path.delimiter).map((r) => r.trim()).filter(Boolean).map((r) => path.resolve(r));
  } else {
    roots = [cwd, path.resolve(cwd, "..")];
  }

  const limits: Partial<typeof DEFAULT_SCAN_LIMITS> = {};
  const fileLimits = file.limits ?? {};
  for (const key of Object.keys(DEFAULT_SCAN_LIMITS) as Array<keyof typeof DEFAULT_SCAN_LIMITS>) {
    const value = fileLimits[key];
    if (typeof value === "number" && Number.isFinite(value) && value > 0) {
      (limits as Record<string, number>)[key] = value;
    }
  }

  const skipDirNames = Array.isArray(file.skipDirNames) ? file.skipDirNames.filter((n): n is string => typeof n === "string") : [];
  return { roots, limits, skipDirNames };
}

/** 资产库默认路径：var/assets.sqlite（*.sqlite 已被 .gitignore 覆盖）。 */
export function defaultAssetsDbPath(cwd: string = process.cwd()): string {
  return path.resolve(cwd, "var", "assets.sqlite");
}

/** 配置 + 扫描参数的合并形态。 */
export function scanOptionsFromConfig(cwd: string = process.cwd()): ScanOptions {
  const config = resolveScanConfig(cwd);
  return {
    roots: config.roots,
    ...config.limits,
    ...(config.skipDirNames.length > 0 ? { skipDirNames: config.skipDirNames } : {}),
  };
}
