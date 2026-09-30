/** Y 线流水线单测：离线全链路（4 源回放 → 解析 → 归并 → 闸门 → 总线可读回）。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryEventStore } from "@safetrace/shared";
import type { FallbackEvent, IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { runIngestOnce } from "../src/pipeline.js";

test("pipeline：离线全链路，总线可读回 raw.docs / intel.items / dq.verdicts / fallback.events", async () => {
  const store = new MemoryEventStore();
  const res = await runIngestOnce({ store, offline: true });

  // —— 结果计数 ——
  assert.equal(res.fetched.length, 5); // 五个 active 源全部回放（含 E-01 第 7 源 ubuntu_usn）
  assert.equal(res.parsed.length, 7); // KEV/NVD/OSV/cve.org 各 1 条 + USN fixture 3 条公告
  assert.equal(res.merged.length, 1); // 同一 CVE 的五源报道归并为一条
  assert.equal(res.verdicts.length, 1);
  assert.equal(res.fallbackEvents.length, 5); // 每个源一次 fixture 回放降级
  assert.equal(res.degraded_to, "fixture"); // 红线：降级在响应对象上显式可见

  // —— 归并结果：多源引用 + 强标识齐全 ——
  const merged = res.merged[0]!;
  assert.equal(merged.intel_id, "intel_kev_cve_2021_44228");
  assert.deepEqual(merged.cve_ids, ["CVE-2021-44228", "CVE-2021-45046"]); // USN-5197-1 带出姊妹 CVE
  assert.deepEqual(merged.ghsa_ids, ["GHSA-jfh8-c2jp-5v3q"]);
  assert.deepEqual([...merged.source_ids].sort(), ["cisa_kev", "cve_org", "nvd_cve", "osv", "ubuntu_usn"]);
  assert.deepEqual([...(merged.aliases ?? [])].sort(), ["USN-5192-1", "USN-5192-2", "USN-5197-1"]);
  assert.equal(merged.published_at, "2021-12-10T00:00:00.000Z"); // 取最早（KEV）
  assert.ok(merged.raw_refs.length === 5);
  assert.match(merged.first_seen_at, /Z$/);
  assert.equal(res.verdicts[0]!.verdict, "pass"); // 干净数据放行

  // —— 总线读回 ——
  const rawDocs = await store.read<RawDoc>("raw.docs");
  const intels = await store.read<IntelItem>("intel.items");
  const verdicts = await store.read<QualityVerdict>("dq.verdicts");
  const falls = await store.read<FallbackEvent>("fallback.events");
  assert.equal(rawDocs.length, 5);
  assert.equal(intels.length, 1);
  assert.equal(verdicts.length, 1);
  assert.equal(falls.length, 5);
  assert.deepEqual(intels[0]!.payload.source_ids, merged.source_ids);
  assert.equal(verdicts[0]!.payload.item_id, merged.intel_id);

  // —— 降级显式可见：degraded_of=fixture / L2 / label 写明"离线回放预置样本" ——
  for (const env of falls) {
    assert.equal(env.payload.layer, "L2");
    assert.equal(env.payload.degraded_of, "fixture");
    assert.match(env.payload.degraded_state.label, /离线回放预置样本/);
    assert.equal(env.payload.user_visible, true);
  }

  // —— trace_id 贯穿、causation_id 串联 ——
  const all = [...rawDocs, ...intels, ...verdicts, ...falls];
  assert.equal(new Set(all.map((e) => e.trace_id)).size, 1);
  assert.equal(intels[0]!.causation_id, rawDocs[0]!.event_id); // intel.items ← raw.docs
  assert.equal(verdicts[0]!.causation_id, intels[0]!.event_id); // dq.verdicts ← intel.items
  assert.equal(falls[0]!.causation_id, rawDocs[0]!.event_id); // fallback.events ← raw.docs

  // —— lineage：每个 stage 有 input/output hash、多源归并保留多个父节点 ——
  assert.ok(res.trace_id.startsWith("tr_"));
  const lineage = await store.readLineage(res.trace_id);
  const stageRows = (stage: string) => lineage.filter((row) => row.stage === stage);
  // 5 个 active 源（E-01 第 7 源 ubuntu_usn 接入后）：fetch/parse/fallback 各一行
  assert.equal(stageRows("ingest.fetch").length, 5);
  assert.equal(stageRows("ingest.parse").length, 5);
  assert.equal(stageRows("ingest.fallback").length, 5);
  assert.equal(stageRows("ingest.dedupe").length, 1);
  assert.equal(stageRows("ingest.dq1").length, 1);
  assert.ok(stageRows("ingest.fetch").every((row) => row.status === "degraded"));
  for (const row of stageRows("ingest.fetch")) {
    assert.ok(row.output_refs.some((ref) => ref.kind === "RawPayload" && /^[a-f0-9]{64}$/.test(ref.sha256 ?? "")));
  }
  const parseLineage = stageRows("ingest.parse")[0]!;
  assert.ok(parseLineage.parent_lineage_ids.length >= 2, "parse links fetch artifact and raw.docs event");
  const dqLineage = stageRows("ingest.dq1")[0]!;
  assert.ok(res.lineage_parent_by_intel_id[res.merged[0]!.intel_id]);
  assert.ok(res.causation_by_intel_id[res.merged[0]!.intel_id]);
  assert.ok(dqLineage.parent_lineage_ids.length >= 6, "multi-source merged DQ result links all five parser records plus dedupe");
  assert.ok(dqLineage.output_refs.some((ref) => ref.kind === "QualityVerdict" && /^[a-f0-9]{64}$/.test(ref.sha256 ?? "")));
  assert.ok(!JSON.stringify(lineage).includes("CVE-2021-44228 Log4Shell"), "lineage stores IDs/hashes, not duplicated raw/advisory text");

  // —— RawDoc 携带 Y2 解析告警 ——
  const kevDoc = rawDocs.find((e) => e.payload.source_id === "cisa_kev")!.payload;
  assert.ok((kevDoc.parse_warnings ?? []).length >= 1);
});

test("pipeline：sourceIds 过滤只跑指定源（不降级其他源）", async () => {
  const store = new MemoryEventStore();
  const res = await runIngestOnce({ store, offline: true, sourceIds: ["cisa_kev"] });
  assert.equal(res.fetched.length, 1);
  assert.equal(res.parsed.length, 1);
  assert.equal(res.merged.length, 1);
  assert.equal(res.fallbackEvents.length, 1);
  assert.equal(res.degraded_to, "fixture");
  assert.deepEqual(res.merged[0]!.source_ids, ["cisa_kev"]);
  assert.deepEqual(res.verdicts[0]!.verdict, "pass");
  assert.equal((await store.read("intel.items")).length, 1);
  assert.equal((await store.read("raw.docs")).length, 1);
});

test("pipeline：planned 源（ghsa/arxiv）无采集器，指定即静默跳过", async () => {
  const store = new MemoryEventStore();
  const res = await runIngestOnce({ store, offline: true, sourceIds: ["ghsa", "arxiv"] });
  assert.equal(res.fetched.length, 0);
  assert.equal(res.parsed.length, 0);
  assert.equal(res.merged.length, 0);
  assert.equal(res.verdicts.length, 0);
  assert.equal(res.degraded_to, undefined); // 无抓取即无降级：不标记
  assert.equal((await store.read("raw.docs")).length, 0);
});
