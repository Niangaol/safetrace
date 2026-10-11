/**
 * Q5 解决方案规划：问答不只做「问题分析」，还要结合本地仓库快照给出三个可执行方向。
 *
 * 三个方向（固定顺序，缺一不可）：
 *   1. upgrade           升级修复：定位清单 → 升级到厂商公告修复版本 → 回归 → 回滚
 *   2. mitigate          临时缓解：无法立即升级时的隔离/停用条件、验证与回退
 *   3. replace_or_remove 替换或移除：盘点引入点、灰度替换、移除与回归
 *
 * 纪律（与资产线/富化线同一套红线，不引入第二套判定逻辑）：
 * - 版本结论只走 @safetrace/assets 的 assessVersionImpact（与资产匹配器共用原语），
 *   禁止用检索相似度或模型自由生成「是否受影响 / 该升到哪一版」；
 * - 只消费已落库的本地扫描快照与已发布情报，零网络、零模型、零资产库写入；
 * - 厂商公告只转述（Ubuntu USN / CISA KEV），明确标注「尚未验证」；不跨生态映射包名；
 * - 不猜版本：范围约束下界（^3.5.0）必须显式提示先锁定实际安装版本；
 * - 不猜影响：unknown ≠ 安全；没有命中组件也不代表不受影响；
 * - 隐私：调用方只许传入仓库指纹（哈希），本模块不接收、不输出本机绝对路径；
 * - 扫描降级（git_unavailable / timeout / read_error）必须显式出现在结论里。
 */
import { normalizeName } from "@safetrace/enrich";
import { assessVersionImpact, nameVariants } from "@safetrace/assets";
import { canonicalProductName } from "./q1-intent.js";

export type SolutionDirection = "upgrade" | "mitigate" | "replace_or_remove";
export type SolutionImpact = "affected" | "not_affected" | "unknown";
export type SolutionStepKind = "condition" | "action" | "verify" | "rollback";

/** 情报侧最小形态（IntelItem 子集；保持纯函数可离线测试）。 */
export interface SolutionIntel {
  intel_id: string;
  cve_ids: readonly string[];
  entities: { product: string | null; vendor: string | null; version_range: readonly string[] };
}

/** 本地快照组件（最新一轮扫描）。repo_fingerprint 必须是哈希，禁止绝对路径。 */
export interface SolutionComponentInput {
  ecosystem: string;
  name: string;
  version: string;
  constraint_raw: string;
  version_is_range_floor: boolean;
  /** 仓库内相对清单路径（POSIX），不含用户私有信息。 */
  source_file: string;
  /** 仓库身份指纹（调用方用 sha256Json({repo_path}) 计算后截断）。 */
  repo_fingerprint: string;
  group_id: string;
  run_id: string;
  run_status: "ok" | "partial";
  run_degraded_to: string | null;
}

/** 厂商/机构公告（只允许来自 ubuntu_usn / cisa_kev 的既有产物）。 */
export interface SolutionAdvisory {
  cve_id: string;
  source_id: string;
  source_url: string;
  validation_level: string;
  published_at: string;
  fixed_packages: readonly { name: string; version: string; release?: string }[];
  actions: readonly string[];
}

export interface SolutionSnapshotInfo {
  run_count: number;
  component_count: number;
  latest_finished_at: string | null;
  degraded_runs: readonly { group_id: string; degraded_to: string }[];
}

export interface SolutionPlanInput {
  cve_ids: readonly string[];
  products: readonly string[];
  intel: readonly SolutionIntel[];
  components: readonly SolutionComponentInput[];
  advisories?: readonly SolutionAdvisory[];
  snapshot: SolutionSnapshotInfo;
}

export interface SolutionComponent extends SolutionComponentInput {
  cve_ids: string[];
  intel_id: string;
  /** 情报侧产品标识（归一化前原文）。 */
  product: string;
  /** 情报给出的受影响版本规则原文（OR 连接；无规则为 unavailable）。 */
  rule: string;
  impact: SolutionImpact;
  tested_version: string;
  matched_ranges: string[];
  reason: string;
  vendor_unverified: true;
  /** 生态对应的升级命令（<version> 占位，版本号取自公告来源）；生态不支持时为空串。 */
  upgrade_command: string;
  upgrade_command_supported: boolean;
}

export interface SolutionStep {
  kind: SolutionStepKind;
  text: string;
}

export interface SolutionOption {
  direction: SolutionDirection;
  title: string;
  applicable: boolean;
  /** 不适用的具体原因（证据不足必须写明，不许留空话）。 */
  blockers: string[];
  components: SolutionComponent[];
  steps: SolutionStep[];
  advisories: SolutionAdvisory[];
  limitations: string[];
}

export interface SolutionPlan {
  /** 三个方向是否至少一个可用（无匹配组件时为 false）。 */
  has_plan: boolean;
  targets: { intel_id: string; cve_ids: string[]; product: string }[];
  components: SolutionComponent[];
  /** 经版本规则判定不在受影响范围的组件数（只统计，不当作安全证明）。 */
  not_affected_count: number;
  options: SolutionOption[];
  snapshot: SolutionSnapshotInfo;
  notes: string[];
}

/** 单轮最多展开的组件数；超出只列前 N 个并显式提示截断。 */
export const MAX_PLAN_COMPONENTS = 12;

/** 生态 → 升级命令。<name>/<version> 为占位符；生态不受支持时不编命令。 */
const ECOSYSTEM_UPGRADE_COMMAND: Readonly<Record<string, string>> = {
  npm: "npm install <name>@<version> --save-exact（同步更新 package-lock.json）",
  pypi: "pip install '<name>==<version>'（同步更新 requirements/lock）",
  go: "go get <name>@<version> && go mod tidy",
  cargo: "cargo update -p <name> --precise <version>",
  maven: "在 pom.xml 将 <name> 固定为 <version> 后重新解析依赖",
  composer: "composer require <name>:<version>",
  gem: "Gemfile 固定 <name> 为 <version> 后 bundle install",
  docker: "将镜像/依赖 <name> 固定为 <version> 后重新构建",
  "github-actions": "将 action <name> 固定为 <version> 后重跑工作流",
};

const DIRECTION_TITLE: Readonly<Record<SolutionDirection, string>> = {
  upgrade: "方案一 · 升级修复",
  mitigate: "方案二 · 临时缓解",
  replace_or_remove: "方案三 · 替换或移除",
};

const IMPACT_LABEL: Readonly<Record<SolutionImpact, string>> = {
  affected: "受影响",
  not_affected: "不在已解析的受影响范围内",
  unknown: "无法判定",
};

/** 升级命令：生态未知/不支持时返回 null，调用方必须显式说明而不是编一条命令。 */
export function upgradeCommandFor(ecosystem: string, name: string): string | null {
  const template = ECOSYSTEM_UPGRADE_COMMAND[ecosystem];
  return template ? template.replaceAll("<name>", name) : null;
}

/** 目标情报：漏洞编号优先，其次产品名；都没有返回空（三个方向都标注不适用）。 */
function selectTargets(input: SolutionPlanInput): SolutionIntel[] {
  const cves = new Set(input.cve_ids.map(id => id.trim().toUpperCase()).filter(Boolean));
  if (cves.size > 0) {
    return input.intel
      .filter(item => item.cve_ids.some(id => cves.has(id.trim().toUpperCase())))
      .sort((a, b) => a.intel_id.localeCompare(b.intel_id));
  }
  const asked = new Set(input.products.map(product => nameVariants(canonicalProductName(product))).flat());
  if (asked.size === 0) return [];
  return input.intel
    .filter(item => {
      const product = canonicalProductName(item.entities.product ?? "");
      return product !== "" && nameVariants(product).some(variant => asked.has(variant));
    })
    .sort((a, b) => a.intel_id.localeCompare(b.intel_id));
}

function advisoriesFor(advisories: readonly SolutionAdvisory[] | undefined, cveIds: readonly string[]): SolutionAdvisory[] {
  const wanted = new Set(cveIds.map(id => id.trim().toUpperCase()));
  return (advisories ?? [])
    .filter(advisory => wanted.has(advisory.cve_id.trim().toUpperCase()))
    .sort((a, b) => (a.cve_id + a.source_id + a.source_url).localeCompare(b.cve_id + b.source_id + b.source_url));
}

function sortComponents(components: SolutionComponent[]): SolutionComponent[] {
  return [...components].sort((a, b) =>
    a.ecosystem.localeCompare(b.ecosystem)
    || a.name.localeCompare(b.name)
    || a.repo_fingerprint.localeCompare(b.repo_fingerprint)
    || a.source_file.localeCompare(b.source_file)
    || a.intel_id.localeCompare(b.intel_id));
}

/**
 * 生成三个方向的解决方案。纯函数：同样的快照 + 同样的输入 → 同样的输出。
 * 任何无法用本地证据支撑的方向都以 applicable=false + blockers 显式说明。
 */
export function buildSolutionPlan(input: SolutionPlanInput): SolutionPlan {
  const notes: string[] = [];
  const targets = selectTargets(input);
  const components: SolutionComponent[] = [];
  const seen = new Set<string>();
  let notAffected = 0;

  if (targets.length === 0) {
    notes.push("未提供可对齐的漏洞编号或产品名，无法把方案绑定到本地组件；请补充 CVE 编号或产品名后重问。");
  }
  if (input.snapshot.component_count === 0 || input.components.length === 0) {
    notes.push("本地资产快照为空或该分组尚未扫描：请先在资产页执行扫描，否则无法给出组件级方案。");
  }
  for (const run of input.snapshot.degraded_runs) {
    notes.push("分组 " + run.group_id + " 的扫描降级为 " + run.degraded_to + "：该组组件清单可能不完整，结论按不完整快照给出。");
  }

  for (const intel of targets) {
    const product = canonicalProductName(intel.entities.product ?? "");
    if (!normalizeName(product)) continue;
    const variants = new Set(nameVariants(product));
    const candidate = input.components.filter(component => nameVariants(component.name).some(variant => variants.has(variant)));
    // 同名组件跨生态不能证明产品身份（与资产收据同一口径）。
    const ecosystems = [...new Set(candidate.map(component => component.ecosystem))].sort();
    const collision = ecosystems.length > 1;
    for (const component of candidate) {
      const key = [intel.intel_id, component.ecosystem, normalizeName(component.name), component.repo_fingerprint, component.source_file].join("|");
      if (seen.has(key)) continue;
      seen.add(key);
      const verdict = collision
        ? {
            status: "unknown" as const,
            tested_version: component.version,
            matched_ranges: [] as string[],
            rule: intel.entities.version_range.length ? intel.entities.version_range.join(" OR ") : "unavailable",
            reason: "同名组件跨生态（" + ecosystems.join("、") + "），不能证明产品身份",
          }
        : assessVersionImpact(
            { intel_id: intel.intel_id, cve_ids: [...intel.cve_ids], entities: { product, vendor: intel.entities.vendor, version_range: [...intel.entities.version_range] } },
            component,
          );
      if (verdict.status === "not_affected") {
        notAffected += 1;
        continue;
      }
      const command = upgradeCommandFor(component.ecosystem, component.name);
      components.push({
        ...component,
        cve_ids: [...intel.cve_ids],
        intel_id: intel.intel_id,
        product,
        rule: verdict.rule,
        impact: verdict.status,
        tested_version: verdict.tested_version,
        matched_ranges: [...verdict.matched_ranges],
        reason: verdict.reason,
        vendor_unverified: true,
        upgrade_command: command ?? "",
        upgrade_command_supported: command !== null,
      });
    }
  }

  const ordered = sortComponents(components);
  const shown = ordered.slice(0, MAX_PLAN_COMPONENTS);
  if (ordered.length > shown.length) {
    notes.push("命中组件 " + ordered.length + " 个，本文只展开前 " + shown.length + " 个（按生态/名称排序）；完整清单见资产页组件查询。");
  }
  const cveIds = [...new Set(shown.flatMap(component => component.cve_ids))];
  const advisories = advisoriesFor(input.advisories, cveIds);
  const blockers = shown.length === 0
    ? [notAffected > 0
        ? "本地快照中同名组件均按版本规则判定不在受影响范围（本地规则判定，不是厂商确认）；若实际安装版本与清单不一致，请先锁定版本再问。"
        : targets.length === 0
          ? "问题里没有可对齐的漏洞编号或产品名，无法定位本地组件。"
          : "本地快照中未发现与这些情报产品匹配的组件（未覆盖、未扫描或产品名不一致均可能）；这不代表不受影响。"]
    : [];

  const sharedLimitations = [
    "版本与影响结论由本地扫描 + 已发布情报的确定性规则产出；厂商身份未经本地核实（vendor_unverified 恒为 true）。",
    "本系统只解析依赖清单，不执行代码、不安装补丁、不验证修复或缓解有效性。",
  ];
  if (shown.length > 0 && advisories.length === 0) {
    sharedLimitations.push("未检索到厂商/机构公告的修复版本，升级目标版本需人工确认，不得凭推断填写。");
  }

  const upgrade: SolutionOption = {
    direction: "upgrade",
    title: DIRECTION_TITLE.upgrade,
    applicable: shown.length > 0,
    blockers,
    components: shown,
    advisories,
    steps: shown.length === 0 ? [] : [
      ...(shown.some(component => component.version_is_range_floor)
        ? [{ kind: "condition" as const, text: "先锁定实际安装版本：以下组件的清单版本只是范围约束下界（如 ^3.5.0），实际安装版本可能更高；请用 lock 文件或依赖树确认后再决定升级目标。" }]
        : []),
      { kind: "action", text: "在对应清单中把组件升级到适用于你的生态与版本线的修复版本（版本号见下方「公告来源」，把命令里的 <version> 替换为公告版本；无公告时由人工确认）。" },
      { kind: "action", text: "同步更新 lock 文件并提交，保证团队其他成员与 CI 拿到同一版本。" },
      { kind: "verify", text: "回归：运行该仓库既有测试与构建流程；本系统不执行代码，回归结果需人工确认。" },
      { kind: "verify", text: "重新扫描（资产页「扫描」或 POST /api/v1/assets/scan）：确认该组件版本已离开受影响区间；扫描只证明版本，不证明修复有效。" },
      { kind: "rollback", text: "回归不通过时把版本固定回升级前版本（保留升级前 lock 备份）并重新扫描，回到已知状态后再评估其他方向。" },
    ],
    limitations: [
      ...sharedLimitations,
      "公告中的修复包名属于公告生态（如 Ubuntu 包名），本系统不做跨生态包名映射，请自行选择对应生态的版本。",
    ],
  };

  const mitigate: SolutionOption = {
    direction: "mitigate",
    title: DIRECTION_TITLE.mitigate,
    applicable: shown.length > 0,
    blockers,
    components: shown,
    advisories,
    steps: shown.length === 0 ? [] : [
      { kind: "condition", text: "适用前提：暂时无法升级（升级会破坏兼容性、组件是间接依赖、公告修复版本尚未覆盖你的版本线、或没有可用补丁）。" },
      { kind: "action", text: "收敛暴露面：按该组件的实际用途关闭或禁用相关功能，并用网络策略限制其可达性；本系统只解析清单、不解析源码调用，能否安全禁用需人工确认。" },
      { kind: "action", text: "若该组件当前未被使用，先从构建链路摘除对应引入点，确认构建与测试仍通过。" },
      { kind: "verify", text: "验证功能影响：确认关闭或隔离后业务功能符合预期，并记录影响范围。" },
      { kind: "verify", text: "重新扫描：组件仍在快照中且版本未变时，本系统仍会判定为受影响；缓解有效性无法由本系统证明，需人工评估或渗透测试确认。" },
      { kind: "rollback", text: "若缓解影响业务：恢复原配置，登记为「已接受风险」并约定升级窗口，不要静默保留高风险状态。" },
    ],
    limitations: [
      ...sharedLimitations,
      "缓解措施是通用方向，不是漏洞专属补丁；关闭功能可能影响业务，需人工权衡。",
    ],
  };

  const replaceOrRemove: SolutionOption = {
    direction: "replace_or_remove",
    title: DIRECTION_TITLE.replace_or_remove,
    applicable: shown.length > 0,
    blockers,
    components: shown,
    advisories: [],
    steps: shown.length === 0 ? [] : [
      { kind: "action", text: "盘点引入点：以上清单路径（source_file）是 manifest 层的引入位置；真实调用点需静态分析或人工确认，本系统不解析源码。" },
      { kind: "action", text: "选型替代：候选替代依赖由人工确认；本系统不访问外部注册表、不推荐具体替代包，避免无依据推荐。" },
      { kind: "action", text: "灰度替换：先在一个仓库/一个分组替换并跑通回归，再推广到其他分组。" },
      { kind: "verify", text: "替换后重新扫描：确认旧组件从 manifest 消失、无残留告警；替代库自身的安全性与维护状态需人工评估。" },
      { kind: "rollback", text: "回退到原依赖与版本，保留替换前的 lock 备份。" },
    ],
    limitations: [
      ...sharedLimitations,
      "本系统不评估替代库的安全性与维护状态，迁移成本需人工评估。",
    ],
  };

  return {
    has_plan: shown.length > 0,
    targets: targets.map(intel => ({ intel_id: intel.intel_id, cve_ids: [...intel.cve_ids], product: intel.entities.product ?? "" })),
    components: ordered,
    not_affected_count: notAffected,
    options: [upgrade, mitigate, replaceOrRemove],
    snapshot: input.snapshot,
    notes,
  };
}

/** 三个方向是否至少一个可执行（供调用方决定是否追加答案段落）。 */
export function solutionPlanHasContent(plan: SolutionPlan): boolean {
  return plan.options.some(option => option.applicable);
}

function componentLine(component: SolutionComponent): string {
  const location = "清单 `" + component.source_file + "`，仓库指纹 `" + component.repo_fingerprint + "`";
  const verdict = component.impact === "affected"
    ? "满足受影响版本规则 " + component.rule
    : "无法判定：" + component.reason;
  const caveat = component.version_is_range_floor ? "；版本为范围约束下界（原约束 " + component.constraint_raw + "）" : "";
  const scan = component.run_status === "partial" ? "；所属扫描降级 " + component.run_degraded_to : "";
  return "- `" + component.ecosystem + ":" + component.name + "@" + (component.version || "未锁定") + "` — " + location + "；" + verdict + caveat + scan + "。";
}

/** 组件判定汇总：混合状态时逐项计数，不用第一个组件的状态概括全部。 */
function impactSummary(components: SolutionComponent[]): string {
  const counts = new Map<SolutionImpact, number>();
  for (const component of components) counts.set(component.impact, (counts.get(component.impact) ?? 0) + 1);
  return [...counts].map(([impact, count]) => IMPACT_LABEL[impact] + " " + count + " 个").join("、");
}

function advisoryLine(advisory: SolutionAdvisory): string {
  const fixed = [...new Set(advisory.fixed_packages.map(pkg => pkg.name + (pkg.release ? " (" + pkg.release + ")" : "") + " " + pkg.version))];
  return "- " + advisory.source_id + " · " + advisory.cve_id + " · " + advisory.validation_level + " · 发布 " + advisory.published_at
    + (fixed.length ? " · 声明的修复包：" + fixed.join("、") : " · 未给出修复包版本")
    + " · 来源 " + advisory.source_url + "（厂商/机构声明，尚未验证）";
}

/** 渲染为 Markdown 段落（由服务端确定性拼接，模型不得改写）。 */
export function renderSolutionPlanMarkdown(plan: SolutionPlan): string {
  const lines: string[] = ["## 解决方案（基于本地仓库快照）"];
  const snapshot = plan.snapshot;
  lines.push("",
    "本地快照：" + snapshot.run_count + " 个分组、" + snapshot.component_count + " 个组件"
    + (snapshot.latest_finished_at ? "，最近扫描完成于 " + snapshot.latest_finished_at : "，尚无完成的扫描")
    + (snapshot.degraded_runs.length ? "；其中 " + snapshot.degraded_runs.map(run => run.group_id + "=" + run.degraded_to).join("、") + " 扫描降级" : "")
    + "。",
    "",
    "以下三个方向按可执行性排列，均为**待执行方案**，不是已验证修复；版本与影响结论来自本地扫描 + 已发布情报。");
  for (const option of plan.options) {
    lines.push("", "### " + option.title);
    if (!option.applicable) {
      lines.push("", "本轮不适用：" + (option.blockers[0] ?? "缺少可绑定的本地组件证据。"));
      continue;
    }
    lines.push("", "**适用组件**（" + option.components.length + " 个；" + impactSummary(option.components) + "；厂商身份未经本地核实）：");
    for (const component of option.components) lines.push(componentLine(component));
    // 公告只在升级方向展开：版本号只对"升到哪一版"有意义，缓解/替换方向重复列出只是噪声。
    if (option.direction === "upgrade" && option.advisories.length > 0) {
      lines.push("", "**公告来源**（升级目标版本从这里取，本系统不做跨生态包名映射）：");
      for (const advisory of option.advisories) lines.push(advisoryLine(advisory));
    }
    lines.push("", "**步骤**：");
    option.steps.forEach((step, index) => {
      const tag = step.kind === "condition" ? "前置" : step.kind === "action" ? "操作" : step.kind === "verify" ? "验证" : "回滚";
      lines.push((index + 1) + ". 【" + tag + "】" + step.text);
    });
    if (option.direction === "upgrade") {
      const commands = [...new Set(option.components.filter(component => component.upgrade_command_supported).map(component => component.upgrade_command))];
      if (commands.length > 0) {
        lines.push("", "**升级命令模板**（把 <version> 替换为公告里适用于该生态与版本线的版本）：");
        for (const command of commands) lines.push("- `" + command + "`");
      } else {
        lines.push("", "**升级命令模板**：未识别到受支持的生态，请按该生态的包管理器手工升级（不编造命令）。");
      }
    }
    lines.push("", "**局限**：");
    for (const limitation of option.limitations) lines.push("- " + limitation);
  }
  if (plan.notes.length > 0) {
    lines.push("", "**快照与口径说明**：");
    for (const note of plan.notes) lines.push("- " + note);
  }
  if (plan.not_affected_count > 0) {
    lines.push("- 另有 " + plan.not_affected_count + " 个同名组件按版本规则判定不在受影响范围；这是本地规则判定，不是厂商确认的安全证明。");
  }
  lines.push("- 没有命中告警不代表不受影响：未覆盖的目录、未扫描的分组、无法解析的版本都按 unknown 处理。");
  return lines.join("\n");
}
