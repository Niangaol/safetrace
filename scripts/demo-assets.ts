import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { IntelItem } from "@safetrace/shared";
import { matchAssets, type DemoAsset } from "../src/enrich/src/f2-assets.js";

const root = process.cwd();
const item = JSON.parse(readFileSync(join(root, "fixtures/intelitem.sample.json"), "utf8")) as IntelItem;
const fixture = JSON.parse(readFileSync(join(root, "fixtures/assets/demo-assets.v0.json"), "utf8")) as {
  fixture_id: string;
  data_class: string;
  authorization: string;
  assets: DemoAsset[];
};
const matches = matchAssets(item, fixture.assets);
const counts = matches.reduce<Record<string, number>>((total, match) => {
  total[match.status] = (total[match.status] ?? 0) + 1;
  return total;
}, {});

console.log(`SafeTrace F2 演示 · ${fixture.fixture_id}`);
console.log("范围：仅使用本地合成演示资产，不读取真实资产，不进行网络扫描或探测。");
console.log(`情报：${item.cve_ids.join(", ") || item.intel_id} · ${item.entities.product ?? "产品未知"}`);
console.log(`${matches.length} 项结果：受影响=${counts.affected ?? 0}, 不受影响=${counts.not_affected ?? 0}, 待核实=${counts.unknown ?? 0}`);
const labels = { affected: "受影响", not_affected: "不受影响", unknown: "待核实" } as const;
for (const match of matches) {
  console.log(`${match.asset_id}\t${labels[match.status]}\t${match.service}\t${match.evidence.reason}`);
}
