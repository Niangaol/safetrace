import assert from "node:assert/strict";
import test from "node:test";
import type { IntelItem } from "@safetrace/shared";
import { matchAssets, type DemoAsset } from "../src/f2-assets.js";

const makeItem = (version_range: string[], overrides: Partial<IntelItem["entities"]> = {}) => ({
  intel_id: "intel-demo-log4shell",
  cve_ids: ["CVE-2021-44228"],
  entities: {
    product: "log4j-core",
    vendor: "apache",
    version_range,
    cwe: [],
    cpes: [],
    ...overrides,
  },
});

const makeAsset = (version: string, overrides: Partial<DemoAsset> = {}): DemoAsset => ({
  asset_id: "demo-asset",
  product: "log4j-core",
  vendor: "apache",
  version,
  service: "demo-service",
  criticality: "high",
  ...overrides,
});

test("F2：包含边界的比较符命中边界版本，并排除下一个版本", () => {
  const matches = matchAssets(makeItem(["<=2.14.1"]), [makeAsset("2.14.1"), makeAsset("2.14.2")]);
  assert.deepEqual(matches.map((match) => match.status), ["affected", "not_affected"]);
  assert.deepEqual(matches[0]?.evidence.matched_ranges, ["<=2.14.1"]);
});

test("F2：单条范围内的多个比较条件按 AND 处理", () => {
  const matches = matchAssets(makeItem([">=2.0.0 <2.14.2"]), [makeAsset("2.14.1"), makeAsset("2.14.2"), makeAsset("1.9.9")]);
  assert.deepEqual(matches.map((match) => match.status), ["affected", "not_affected", "not_affected"]);
});

test("F2：多条备选范围按 OR 处理", () => {
  const matches = matchAssets(makeItem(["<2.0.0", "2.14.1"]), [makeAsset("1.9.0"), makeAsset("2.14.1"), makeAsset("2.14.2")]);
  assert.deepEqual(matches.map((match) => match.status), ["affected", "affected", "not_affected"]);
});

test("F2：不支持的资产版本和无法解析的规则保持待核实", () => {
  const matches = matchAssets(makeItem(["<2.14.2"]), [makeAsset("2.14.1-rc1"), makeAsset("2.x")]);
  assert.deepEqual(matches.map((match) => match.status), ["unknown", "unknown"]);
  assert.match(matches[0]?.evidence.reason ?? "", /格式不受支持/);
});

test("F2：产品不匹配时排除，同名产品但厂商冲突时待核实", () => {
  const matches = matchAssets(makeItem(["<=2.14.1"]), [
    makeAsset("2.14.1", { product: "nginx" }),
    makeAsset("2.14.1", { vendor: "demo-vendor-b" }),
  ]);
  assert.deepEqual(matches.map((match) => match.status), ["not_affected", "unknown"]);
});

test("F2：同名产品缺少厂商标识时保持待核实", () => {
  const matches = matchAssets(makeItem(["<=2.14.1"]), [makeAsset("2.14.1", { vendor: null })]);
  assert.equal(matches[0]?.status, "unknown");
});

test("F2：存在无法解析的范围时不得作出否定结论", () => {
  const matches = matchAssets(makeItem(["<2.0.0", "<2.14.x"]), [makeAsset("2.14.1")]);
  assert.equal(matches[0]?.status, "unknown");
});


test("F2：互相矛盾的版本边界不能得出不受影响结论", () => {
  const matches = matchAssets(makeItem([">=2.0.0 <1.0.0"]), [makeAsset("2.14.1")]);
  assert.equal(matches[0]?.status, "unknown");
});
