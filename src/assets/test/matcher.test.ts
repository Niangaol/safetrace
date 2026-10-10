import assert from "node:assert/strict";
import test from "node:test";
import { matchComponent, matchComponents, componentKey, buildProductIndex, type IntelLite, type MatchedComponent } from "../src/matcher.js";

const item = (product: string | null, version_range: string[], cve_ids: string[] = ["CVE-2024-0001"]): IntelLite => ({
  intel_id: "intel-1",
  cve_ids,
  entities: { product, vendor: "somevendor", version_range },
});

const comp = (name: string, version: string, constraint_raw = version, floor = false, ecosystem: MatchedComponent["ecosystem"] = "npm"): MatchedComponent => ({
  ecosystem,
  name,
  version,
  constraint_raw,
  version_is_range_floor: floor,
  source_file: "package.json",
  repo_path: "D:/demo/repo",
});

test("affected：产品名匹配且版本落入受影响区间", () => {
  const match = matchComponent(item("vue", ["<3.5.0"]), comp("vue", "3.4.21"));
  assert.equal(match.status, "affected");
  assert.deepEqual(match.matched_ranges, ["<3.5.0"]);
  assert.equal(match.vendor_unverified, true, "本地扫描不携带厂商身份，必须标注未核实");
  assert.equal(match.component_key, "npm:vue");
});

test("not_affected：精确锁定版本在区间外", () => {
  const match = matchComponent(item("vue", ["<3.5.0"]), comp("vue", "3.5.0"));
  assert.equal(match.status, "not_affected");
  assert.deepEqual(match.matched_ranges, []);
});

test("unknown：组件未锁定具体版本", () => {
  const match = matchComponent(item("vue", ["<3.5.0"]), comp("vue", "", "*", true));
  assert.equal(match.status, "unknown");
  assert.match(match.reason, /未提供具体版本/);
});

test("unknown：版本为范围下界且未命中——不猜实际版本", () => {
  const match = matchComponent(item("vue", ["<3.4.0"]), comp("vue", "3.5.0", "^3.5.0", true));
  assert.equal(match.status, "unknown");
  assert.match(match.reason, /范围下界/);
});

test("affected：范围下界命中时结论带 semver 提示", () => {
  const match = matchComponent(item("vue", ["<4.0.0"]), comp("vue", "3.5.0", "^3.5.0", true));
  assert.equal(match.status, "affected");
  assert.match(match.reason, /实际安装版本可能更高/);
});

test("unknown：情报缺版本规则", () => {
  const match = matchComponent(item("vue", []), comp("vue", "3.4.0"));
  assert.equal(match.status, "unknown");
  assert.match(match.reason, /未提供受影响版本规则/);
});

test("unknown：版本规则无法解析", () => {
  const match = matchComponent(item("vue", ["<3.4.x || ～3.3"]), comp("vue", "3.4.21"));
  assert.equal(match.status, "unknown");
  assert.match(match.reason, /无法解析/);
});

test("not_affected：产品标识不匹配", () => {
  const match = matchComponent(item("react", ["<18.0.0"]), comp("vue", "3.4.0"));
  assert.equal(match.status, "not_affected");
});

test("npm 作用域包：@scope/name 与裸名都能匹配", () => {
  const scoped = comp("@vue/cli", "5.0.8");
  assert.equal(matchComponent(item("@vue/cli", ["<5.0.9"]), scoped).status, "affected");
  assert.equal(matchComponent(item("cli", ["<5.0.9"]), scoped).status, "affected");
});

test("多 CVE 情报：cve_ids 全量带入匹配结果", () => {
  const match = matchComponent(item("vue", ["<3.5.0"], ["CVE-2024-0001", "CVE-2024-0002"]), comp("vue", "3.4.21"));
  assert.deepEqual(match.cve_ids, ["CVE-2024-0001", "CVE-2024-0002"]);
});

test("批量匹配：索引加速，只产出 affected", () => {
  const items = [item("vue", ["<3.5.0"]), item("react", ["<18.0.0"]), item(null, ["<1.0.0"])];
  const components = [comp("vue", "3.4.21"), comp("react", "18.3.1"), comp("vue", "3.5.0"), comp("lodash", "4.17.21")];
  const matches = matchComponents(items, components);
  assert.equal(matches.length, 1);
  assert.equal(matches[0]!.name, "vue");
  assert.equal(matches[0]!.version, "3.4.21");
  const index = buildProductIndex(items);
  assert.ok(index.has("vue"));
  assert.ok(!index.has(""), "product 为 null 的情报不进索引");
});

test("componentKey：归一化生态+名称", () => {
  assert.equal(componentKey("npm", "Vue.js"), "npm:vuejs");
  assert.equal(componentKey("maven", "org.springframework.boot:spring-boot-starter-web"), "maven:orgspringframeworkbootspringbootstarterweb");
});
