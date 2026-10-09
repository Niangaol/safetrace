/**
 * 本地资产扫描 · 类型定义（资产快照线 A 线）
 *
 * 定位：SafeTrace 的"本地资产盘点"能力——扫描本机 git 仓库/项目目录，
 * 解析依赖清单生成技术栈快照，再与本地情报库做确定性漏洞匹配。
 *
 * 合规边界（与 F2 富化线一致）：
 * - 只读取本地 manifest 文件与 git 本地元信息，不发起任何网络探测；
 * - 不猜影响结论：版本无法解析或情报缺版本规则时一律 unknown；
 * - 降级必须显式：git 不可用、超时、目录不可读都记录在 skipped/degraded_to。
 */

export type Ecosystem =
  | "npm"
  | "pypi"
  | "go"
  | "cargo"
  | "maven"
  | "composer"
  | "gem"
  | "docker"
  | "github-actions";

/** 清单里解析出的一个依赖组件。version 为空串表示未锁定具体版本。 */
export interface Component {
  ecosystem: Ecosystem;
  name: string;
  /** 具体版本字面量；无法锁定时为空串（匹配时按 unknown 处理）。 */
  version: string;
  /** 原始约束原文，如 ^3.5.0、>=2.0,<3、==1.2.3、${revision}。 */
  constraint_raw: string;
  /** true = version 只是范围约束的下界（如 ^3.5.0），版本结论需带 semver 提示。 */
  version_is_range_floor: boolean;
  /** 相对仓库根的 manifest 路径（POSIX 风格）。 */
  source_file: string;
}

/** 一个被扫描到的项目/git 仓库快照。 */
export interface RepoSnapshot {
  repo_id: string;
  path: string;
  remote_url: string | null;
  branch: string | null;
  head_commit: string | null;
  head_commit_at: string | null;
  is_git: boolean;
  /** git 元信息读取失败/不完整的原因；null = 完整。禁止静默忽略。 */
  git_note: string | null;
  languages: string[];
  frameworks: string[];
  /** 仓库内发现的 manifest 相对路径列表。 */
  manifests: string[];
  components: Component[];
}

export interface ScanSkip {
  path: string;
  reason: string;
}

/** 监控分组：一组扫描根目录 + 启用开关，是资产线的第一类公民。 */
export interface AssetGroup {
  group_id: string;
  name: string;
  /** 该组监控的根目录（绝对路径或相对仓库根的路径，由配置层解析）。 */
  roots: string[];
  enabled: boolean;
  note: string | null;
  created_at: string;
}

export interface ScanRun {
  run_id: string;
  started_at: string;
  finished_at: string;
  /** 本轮扫描所属分组；未分组扫描（如一次性 roots）为 "adhoc"。 */
  group_id: string;
  group_name: string;
  roots: string[];
  status: "ok" | "partial";
  /** 显式降级标记：git_unavailable / timeout / read_error；null = 无降级。 */
  degraded_to: string | null;
  note: string | null;
  repo_count: number;
  component_count: number;
  repos: RepoSnapshot[];
  skipped: ScanSkip[];
}

/** 与 F2 资产匹配一致的三态判定；unknown 表示"不能排除"，不是"不受影响"。 */
export type AssetImpact = "affected" | "not_affected" | "unknown";

/** 一个组件对一条情报的确定性匹配结果。 */
export interface ComponentMatch {
  /** ecosystem + ":" + 归一化组件名，用于告警去重。 */
  component_key: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  repo_path: string;
  /** 命中所属分组（同一组件可在多个分组各自提醒）。 */
  group_id: string;
  source_file: string;
  constraint_raw: string;
  version_is_range_floor: boolean;
  intel_id: string;
  cve_ids: string[];
  status: AssetImpact;
  /** 本地扫描不携带厂商身份，产品名+版本判定成立但厂商未核实时为 true。 */
  vendor_unverified: boolean;
  rule: string;
  tested_version: string;
  matched_ranges: string[];
  reason: string;
}

export interface AssetAlert {
  alert_id: string;
  created_at: string;
  component_key: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  repo_path: string;
  group_id: string;
  cve_id: string;
  intel_id: string;
  /** 由展示层从实时情报视图富化；匹配器不产出。 */
  severity: string | null;
  title: string | null;
  matched_rule: string;
  matched_ranges: string[];
  reason: string;
  vendor_unverified: boolean;
  status: "new" | "seen";
  seen_at: string | null;
  /** 首次产生该提醒的扫描轮次。 */
  first_run_id: string;
}

/** 落入告警的新匹配（插入前的形态）。 */
export interface NewAssetAlert {
  component_key: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  repo_path: string;
  group_id: string;
  cve_id: string;
  intel_id: string;
  matched_rule: string;
  matched_ranges: string[];
  reason: string;
  vendor_unverified: boolean;
  first_run_id: string;
}
