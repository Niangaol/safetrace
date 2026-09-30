/** E-01 第 7 源：USN 采集器与适配器单测（离线回放真实公告样本，不依赖外网）。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import type { FallbackEvent, RawDoc } from "@safetrace/shared";
import { fetchUsn } from "../src/sources/usn.js";
import { parseUsn, USN_RELIABILITY, USN_SOURCE_ID } from "../src/adapters/usn.js";

const FIXTURE_REF = fileURLToPath(new URL("../../../fixtures/sources/usn.sample.json", import.meta.url));

const ISO_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

test("usn 采集器：离线回放 fixture 且显式登记 degraded_to=fixture（红线：禁静默兜底）", async () => {
  const events: FallbackEvent[] = [];
  const raw = await fetchUsn({ offline: true, traceId: "tr_test_usn", emit: (e) => { events.push(e); } });
  assert.ok(raw, "离线必须回放出 RawDoc");
  assert.equal(raw.source_id, USN_SOURCE_ID);
  assert.equal(raw.source_type, "vendor_advisory"); // 契约里已有枚举，未新增
  assert.equal(raw.content_type, "json");
  assert.equal(raw.payload_ref, "fixtures/sources/usn.sample.json");
  assert.equal(raw.external_id, USN_SOURCE_ID + "_fixture");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.degraded_of, "fixture");
  assert.equal(events[0]!.user_visible, true);
});

test("usn 适配器：真实 USN 样本 → 3 条 IntelItem，字段口径逐项可核验", async () => {
  const raw: RawDoc = {
    source_id: USN_SOURCE_ID,
    source_type: "vendor_advisory",
    external_id: "usn_batch_test",
    url: "https://ubuntu.com/security/notices.json",
    fetched_at: new Date().toISOString(),
    content_type: "json",
    payload_ref: "fixtures/sources/usn.sample.json",
  };
  const { items, warnings } = await parseUsn(raw);
  assert.equal(items.length, 3);

  const ids = items.map((i) => i.intel_id).sort();
  assert.deepEqual(ids, ["intel_usn_usn_5192_1", "intel_usn_usn_5192_2", "intel_usn_usn_5197_1"]);

  const first = items.find((i) => i.aliases?.[0] === "USN-5197-1")!;
  assert.deepEqual(first.cve_ids, ["CVE-2021-44228", "CVE-2021-45046"]); // 一条公告多 CVE → 数组承载
  assert.equal(first.source_ids.length, 1);
  assert.equal(first.source_ids[0], USN_SOURCE_ID);
  assert.equal(first.source_reliability, USN_RELIABILITY);
  assert.equal(first.schema_version, "1.0");
  assert.equal(first.title, "Apache Log4j 2 vulnerability");
  assert.match(first.published_at, ISO_Z); // 上游裸串已归一化为带 Z
  assert.match(first.first_seen_at, ISO_Z);
  assert.deepEqual(first.raw_refs, ["fixtures/sources/usn.sample.json"]);
  assert.equal(first.entities.product, "apache-log4j2"); // release_packages 里的 source 包
  assert.equal(first.entities.vendor, null); // USN 不声明上游 vendor → 置空不猜
  assert.deepEqual(first.entities.version_range, []); // 修复版本 ≠ 受影响区间 → 不臆造
  assert.deepEqual(first.entities.cwe, []);
  assert.deepEqual(first.entities.cpes, []);
  assert.ok(warnings.some((w) => w.includes("无时区后缀")), "裸时间戳必须留痕");
  assert.ok(warnings.some((w) => w.includes("version_range")), "version_range 取舍必须留痕");
  assert.ok(warnings.every((w) => w.length > 0));
});

test("usn 适配器：payload 非对象/缺 notices 时只告警不抛错（脏数据不进底座）", async () => {
  const dir = await mktempWith('{"notices": []}', "usn-empty.json");
  const raw: RawDoc = {
    source_id: USN_SOURCE_ID,
    source_type: "vendor_advisory",
    external_id: "x",
    url: "u",
    fetched_at: new Date().toISOString(),
    content_type: "json",
    payload_ref: dir,
  };
  const { items, warnings } = await parseUsn(raw);
  assert.equal(items.length, 0);
  assert.ok(warnings.some((w) => w.includes("notices")));
});

/** 写一个临时 fixture 并返回绝对路径。 */
async function mktempWith(content: string, name: string): Promise<string> {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const path = await import("node:path");
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-usn-"));
  const file = path.join(dir, name);
  await writeFile(file, content, "utf8");
  return file;
}
