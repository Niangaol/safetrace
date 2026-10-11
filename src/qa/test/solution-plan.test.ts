import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildSolutionPlan,
  renderSolutionPlanMarkdown,
  solutionPlanHasContent,
  upgradeCommandFor,
  type SolutionAdvisory,
  type SolutionComponentInput,
  type SolutionIntel,
  type SolutionPlanInput,
} from "../src/solution-plan.js";

const intel: SolutionIntel[] = [
  { intel_id: "intel_log4j", cve_ids: ["CVE-2021-44228"], entities: { product: "log4j", vendor: "Apache", version_range: [">=2.0 <2.15.0"] } },
  { intel_id: "intel_other", cve_ids: ["CVE-2099-0001"], entities: { product: "requests", vendor: null, version_range: ["<2.32.0"] } },
];

const advisory: SolutionAdvisory = {
  cve_id: "CVE-2021-44228",
  source_id: "ubuntu_usn",
  source_url: "https://ubuntu.com/security/notices/USN-5113-1",
  validation_level: "vendor_statement",
  published_at: "2021-12-14",
  fixed_packages: [{ name: "liblog4j2-java", version: "2.17.0-0ubuntu0.20.04.1", release: "focal" }],
  actions: ["Upgrade liblog4j2-java."],
};

const otherCveAdvisory: SolutionAdvisory = { ...advisory, cve_id: "CVE-2099-0001", source_id: "cisa_kev" };

function component(overrides: Partial<SolutionComponentInput> & Pick<SolutionComponentInput, "ecosystem" | "name" | "version">): SolutionComponentInput {
  return {
    constraint_raw: "",
    version_is_range_floor: false,
    source_file: "package.json",
    repo_fingerprint: "deadbeefcafe0000",
    group_id: "safetrace",
    run_id: "run_1",
    run_status: "ok",
    run_degraded_to: null,
    ...overrides,
  };
}

function input(overrides: Partial<SolutionPlanInput> = {}): SolutionPlanInput {
  return {
    cve_ids: ["CVE-2021-44228"],
    products: [],
    intel,
    components: [],
    advisories: [advisory, otherCveAdvisory],
    snapshot: { run_count: 2, component_count: 3, latest_finished_at: "2026-10-09T10:00:00.000Z", degraded_runs: [] },
    ...overrides,
  };
}

test("三个方向齐全：升级修复给出受影响组件、公告来源、步骤与升级命令", () => {
  const plan = buildSolutionPlan(input({
    components: [
      component({ ecosystem: "npm", name: "log4j", version: "2.14.1", constraint_raw: "^2.14.1", version_is_range_floor: true }),
      component({ ecosystem: "npm", name: "log4j", version: "2.16.0", source_file: "web/package.json", repo_fingerprint: "cafe0000deadbeef", group_id: "agentprograms" }),
      component({ ecosystem: "npm", name: "requests", version: "2.31.0" }),
    ],
  }));
  assert.equal(plan.has_plan, true);
  assert.deepEqual(plan.options.map(option => option.direction), ["upgrade", "mitigate", "replace_or_remove"]);
  const [upgrade, mitigate, replaceOrRemove] = plan.options;
  assert.ok(upgrade && mitigate && replaceOrRemove);
  assert.ok(plan.options.every(option => option.applicable));
  // 只有 affected / unknown 进方案；not_affected 只计数不当安全证明
  assert.equal(upgrade!.components.length, 1);
  assert.equal(plan.not_affected_count, 1);
  assert.equal(upgrade!.components[0]!.impact, "affected");
  assert.deepEqual(upgrade!.components[0]!.matched_ranges, [">=2.0 <2.15.0"]);
  assert.equal(upgrade!.components[0]!.upgrade_command_supported, true);
  assert.match(upgrade!.components[0]!.upgrade_command, /^npm install log4j@<version> --save-exact/);
  // 范围约束下界必须作为前置条件显式出现
  assert.equal(upgrade!.steps[0]!.kind, "condition");
  assert.ok(upgrade!.steps.some(step => step.kind === "rollback"));
  assert.ok(upgrade!.steps.some(step => step.kind === "verify"));
  // 公告只取本 CVE 的，且逐条标注尚未验证
  assert.equal(upgrade!.advisories.length, 1);
  assert.equal(upgrade!.advisories[0]!.source_url, "https://ubuntu.com/security/notices/USN-5113-1");
  const markdown = renderSolutionPlanMarkdown(plan);
  assert.match(markdown, /## 解决方案（基于本地仓库快照）/);
  assert.match(markdown, /### 方案一 · 升级修复/);
  assert.match(markdown, /### 方案二 · 临时缓解/);
  assert.match(markdown, /### 方案三 · 替换或移除/);
  assert.match(markdown, /npm install log4j@<version> --save-exact/);
  assert.match(markdown, /liblog4j2-java/);
  assert.match(markdown, /尚未验证/);
  assert.match(markdown, /范围约束下界/);
  assert.match(markdown, /另有 1 个同名组件按版本规则判定不在受影响范围/);
  assert.match(markdown, /2 个分组、3 个组件/);
  assert.match(markdown, /没有命中告警不代表不受影响/);
  assert.equal(solutionPlanHasContent(plan), true);
});

test("同名组件跨生态按 unknown 处理，不猜产品身份", () => {
  const plan = buildSolutionPlan(input({
    components: [
      component({ ecosystem: "npm", name: "log4j", version: "2.14.1" }),
      component({ ecosystem: "pypi", name: "log4j", version: "2.14.1", source_file: "requirements.txt", repo_fingerprint: "feedface00001111" }),
    ],
  }));
  assert.equal(plan.components.length, 2);
  assert.ok(plan.components.every(entry => entry.impact === "unknown"));
  assert.ok(plan.components.every(entry => entry.reason.includes("同名组件跨生态")));
  const markdown = renderSolutionPlanMarkdown(plan);
  assert.match(markdown, /无法判定：同名组件跨生态/);
});

test("没有匹配组件时三个方向都写明不适用原因，不输出步骤", () => {
  const plan = buildSolutionPlan(input({ components: [component({ ecosystem: "npm", name: "requests", version: "2.31.0" })] }));
  assert.equal(plan.has_plan, false);
  assert.equal(solutionPlanHasContent(plan), false);
  assert.equal(plan.options.length, 3);
  assert.ok(plan.options.every(option => !option.applicable && option.blockers.length > 0 && option.steps.length === 0));
  assert.match(plan.options[0]!.blockers[0]!, /未发现与这些情报产品匹配的组件/);
  const markdown = renderSolutionPlanMarkdown(plan);
  assert.match(markdown, /本轮不适用/);
  assert.ok(!markdown.includes("**步骤**"));
});

test("缺少 CVE 或产品名时明确要求补充，不硬猜", () => {
  const plan = buildSolutionPlan(input({ cve_ids: [], products: [], components: [component({ ecosystem: "npm", name: "log4j", version: "2.14.1" })] }));
  assert.deepEqual(plan.targets, []);
  assert.equal(plan.has_plan, false);
  assert.ok(plan.notes.some(note => note.includes("未提供可对齐的漏洞编号或产品名")));
});

test("产品名槽位也能对齐情报（无 CVE 时）", () => {
  const plan = buildSolutionPlan(input({ cve_ids: [], products: ["log4j"], components: [component({ ecosystem: "npm", name: "log4j", version: "2.14.1" })] }));
  assert.equal(plan.has_plan, true);
  assert.equal(plan.components.length, 1);
});

test("空快照与扫描降级必须显式提示", () => {
  const plan = buildSolutionPlan(input({
    components: [],
    snapshot: { run_count: 0, component_count: 0, latest_finished_at: null, degraded_runs: [{ group_id: "agentprograms", degraded_to: "timeout" }] },
  }));
  assert.ok(plan.notes.some(note => note.includes("尚未扫描")));
  assert.ok(plan.notes.some(note => note.includes("timeout")));
  const degraded = buildSolutionPlan(input({
    components: [component({ ecosystem: "npm", name: "log4j", version: "2.14.1", run_status: "partial", run_degraded_to: "git_unavailable" })],
    snapshot: { run_count: 1, component_count: 1, latest_finished_at: null, degraded_runs: [{ group_id: "safetrace", degraded_to: "git_unavailable" }] },
  }));
  assert.match(renderSolutionPlanMarkdown(degraded), /所属扫描降级 git_unavailable/);
  assert.match(renderSolutionPlanMarkdown(degraded), /该组组件清单可能不完整/);
});

test("输出只含仓库指纹，不泄漏本机绝对路径；同一输入结果确定", () => {
  const components = [component({ ecosystem: "npm", name: "log4j", version: "2.14.1", repo_fingerprint: "0123456789abcdef" })];
  const args = input({ components });
  const first = renderSolutionPlanMarkdown(buildSolutionPlan(args));
  const second = renderSolutionPlanMarkdown(buildSolutionPlan(args));
  assert.equal(first, second);
  assert.deepEqual(buildSolutionPlan(args), buildSolutionPlan(args));
  assert.ok(first.includes("0123456789abcdef"));
  assert.ok(!/[A-Z]:\\\\/.test(first));
  assert.ok(!first.includes("Users"));
  assert.ok(!first.includes("AgentPrograms"));
});

test("生态命令模板：受支持生态给出命令，未知生态不编造", () => {
  assert.match(upgradeCommandFor("npm", "log4j")!, /^npm install log4j@<version>/);
  assert.match(upgradeCommandFor("pypi", "requests")!, /^pip install 'requests==<version>'/);
  assert.match(upgradeCommandFor("go", "golang.org/x/net")!, /^go get golang\.org\/x\/net@<version>/);
  assert.equal(upgradeCommandFor("unknown-eco", "whatever"), null);
  const plan = buildSolutionPlan(input({ components: [component({ ecosystem: "mystery", name: "log4j", version: "2.14.1" })] }));
  assert.equal(plan.components[0]!.upgrade_command_supported, false);
  assert.match(renderSolutionPlanMarkdown(plan), /未识别到受支持的生态/);
});
