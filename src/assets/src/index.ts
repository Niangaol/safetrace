/**
 * @safetrace/assets · 本地资产扫描线（A 线）
 *
 * 能力：扫描本机 git 仓库/项目目录 → 技术栈快照 → 与本地情报库确定性匹配 → 漏洞提醒。
 * 合规：只读本地 manifest 与 git 本地元信息，零网络探测；结论不猜，降级显式。
 */
export * from "./types.js";
export * from "./manifests.js";
export * from "./scanner.js";
export * from "./matcher.js";
export * from "./store.js";
export * from "./auto-match.js";
export { resolveScanConfig, defaultAssetsDbPath } from "./config.js";
