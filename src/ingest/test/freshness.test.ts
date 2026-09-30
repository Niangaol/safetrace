/** E-02/E-07：时效统计与连续运行口径单测（全部注入时间，不依赖真等与真网络）。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, appendFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { MemoryEventStore, EventBus } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { computeFreshnessReport, percentile, formatFreshnessTable, SLA_6H_SECONDS } from "../src/freshness.js";
import { computeUptime, readRunLog } from "../src/uptime.js";
import type { RunRecord } from "../src/scheduler.js";

const NOW = new Date("2026-10-05T12:00:00.000Z");
const DAY_MS = 24 * 3600 * 1000;

function item(over: Partial<IntelItem> & { intel_id: string }): IntelItem {
  return {
    cve_ids: [],
    source_ids: ["ubuntu_usn"],
    title: "t",
    published_at: "2026-10-05T00:00:00.000Z",
    first_seen_at: "2026-10-05T01:00:00.000Z",
    entities: { product: null, vendor: null, version_range: [], cwe: [], cpes: [] },
    raw_refs: ["tmp/ingest-cache/live.json"],
    source_reliability: 0.85,
    schema_version: "1.0",
    ...over,
  };
}

async function storeWith(items: IntelItem[]): Promise<MemoryEventStore> {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  for (const it of items) await bus.publish("intel.items", it, { trace_id: "tr_test" });
  return store;
}

test("percentile：最近秩法（n=1/2/20），空集返回 null 而不是 0", () => {
  assert.equal(percentile([], 0.5), null);
  assert.equal(percentile([10], 0.95), 10);
  assert.equal(percentile([1, 2, 3, 4], 0.5), 2); // ceil(0.5*4)=2 → 第 2 个
  assert.equal(percentile(Array.from({ length: 20 }, (_, i) => i + 1), 0.95), 19); // ceil(19)=19
  assert.equal(percentile(Array.from({ length: 20 }, (_, i) => i + 1), 0.5), 10);
});

test("freshness：窗口内 lag 正确聚合，P50/P95/≤6h 可复算", async () => {
  const mk = (id: string, lagSec: number, sourceIds: string[] = ["ubuntu_usn"]): IntelItem => {
    const pub = new Date(NOW.getTime() - DAY_MS).toISOString();
    const seen = new Date(NOW.getTime() - DAY_MS + lagSec * 1000).toISOString();
    return item({ intel_id: id, published_at: pub, first_seen_at: seen, source_ids: sourceIds });
  };
  // 6 个样本：1s / 60s / 3600s / 21600s(=6h 边界) / 43200s(12h) / 86400s-60(≈24h)
  const store = await storeWith([mk("intel_a", 1), mk("intel_b", 60), mk("intel_c", 3600), mk("intel_d", 21600), mk("intel_e", 43200), mk("intel_f", 86340)]);

  const report = await computeFreshnessReport(store, { now: NOW, sources: { registered: 7, active: 5 } });
  assert.equal(report.data_basis, "live");
  assert.equal(report.overall.n, 6);
  assert.equal(report.overall.p50_seconds, 3600); // 最近秩：ceil(0.5*6)=3 → 第 3 小 = 3600
  assert.equal(report.overall.p95_seconds, 86340);
  assert.equal(report.overall.sla_6h_ratio, 0.6667); // 4/6，口径里比例保留 4 位小数
  assert.equal(report.collect.sources_registered, 7);
  assert.equal(report.excluded.fixture_rows, 0);
  const row = report.by_source.find((r) => r.source_id === "ubuntu_usn")!;
  assert.equal(row.n, 6);
  assert.ok(formatFreshnessTable(report).includes("23.98h"), "打表应把 P95 换算成小时");
  assert.equal(report.reference.overall.n, 6); // 无监控起点时严格口径=参考口径
});

test("freshness：fixture 回放行、窗口外、不可解析、负 lag 分别排除并计数", async () => {
  const inWindow = new Date(NOW.getTime() - 2 * 3600 * 1000).toISOString();
  const store = await storeWith([
    item({ intel_id: "intel_ok", published_at: inWindow, first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_fixture", raw_refs: ["fixtures/sources/usn.sample.json"], published_at: inWindow, first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_old", published_at: "2021-12-10T00:00:00.000Z", first_seen_at: NOW.toISOString() }), // 历史 CVE
    item({ intel_id: "intel_bad_ts", published_at: "not-a-date", first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_negative", published_at: NOW.toISOString(), first_seen_at: new Date(NOW.getTime() - 5000).toISOString() }),
  ]);
  const report = await computeFreshnessReport(store, { now: NOW });
  assert.deepEqual(report.excluded, {
    fixture_rows: 1,
    out_of_window: 1,
    published_before_monitor_start: 0,
    unparseable: 1,
    negative_lag: 1,
    duplicate_intel_rows: 0,
  });
  assert.equal(report.overall.n, 1);
  assert.equal(report.data_basis, "live");
  assert.equal(report.monitor_start, null);
});

test("freshness：给出监控起点后，上线前发布的历史 CVE 不计入监测延迟", async () => {
  const monitorStart = "2026-10-04T00:00:00.000Z";
  const before = new Date(Date.parse(monitorStart) - 30 * 3600 * 1000).toISOString();
  const after = new Date(Date.parse(monitorStart) + 600_000).toISOString();
  const store = await storeWith([
    item({ intel_id: "intel_backfill", published_at: before, first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_live", published_at: after, first_seen_at: new Date(Date.parse(after) + 1800_000).toISOString() }),
  ]);
  const report = await computeFreshnessReport(store, { now: NOW, monitorStart });
  assert.equal(report.excluded.published_before_monitor_start, 1);
  assert.equal(report.overall.n, 1);
  assert.equal(report.overall.p50_seconds, 1800); // 上线后的条目：发布 10 分钟后被抓到
});

test("freshness：归并率分母来自运行日志，无日志时为 0（不用抓取批次数冒充）", async () => {
  const store = await storeWith([
    item({ intel_id: "intel_x", published_at: new Date(NOW.getTime() - 60_000).toISOString(), first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_y", published_at: new Date(NOW.getTime() - 60_000).toISOString(), first_seen_at: NOW.toISOString() }),
  ]);
  const noLog = await computeFreshnessReport(store, { now: NOW });
  assert.equal(noLog.collect.raw_items, 0);
  assert.equal(noLog.collect.merge_ratio, 0);
  assert.equal(noLog.collect.intel_items, 2);
  const withLog = await computeFreshnessReport(store, { now: NOW, runTotals: { parsed: 8 } });
  assert.equal(withLog.collect.raw_items, 8);
  assert.equal(withLog.collect.merge_ratio, 0.75); // 1 - 2/8
});

test("freshness：全 fixture 时 data_basis=fixture_only（不许把预置样本当运行证据）", async () => {
  const store = await storeWith([
    item({ intel_id: "intel_f1", raw_refs: ["fixtures/sources/nvd.sample.json"], published_at: new Date(NOW.getTime() - 60_000).toISOString(), first_seen_at: NOW.toISOString() }),
  ]);
  const report = await computeFreshnessReport(store, { now: NOW });
  assert.equal(report.data_basis, "fixture_only");
  assert.equal(report.overall.n, 0);
  assert.equal(report.overall.p50_seconds, null);
  assert.equal(report.overall.sla_6h_ratio, null);
});

test("freshness：同 intel_id 多轮重复上报只算最早一次，其余计入 duplicate", async () => {
  const pub = new Date(NOW.getTime() - 3 * 3600 * 1000).toISOString();
  const store = await storeWith([
    item({ intel_id: "intel_same", published_at: pub, first_seen_at: NOW.toISOString() }),
    item({ intel_id: "intel_same", published_at: pub, first_seen_at: new Date(NOW.getTime() - 60 * 1000).toISOString() }),
  ]);
  const report = await computeFreshnessReport(store, { now: NOW });
  assert.equal(report.overall.n, 1);
  assert.equal(report.excluded.duplicate_intel_rows, 1);
  assert.equal(report.overall.p50_seconds, 10740); // 取更早那次 first_seen：3h − 60s
});

test("uptime：按心跳节拍算覆盖率与最长连续段，降级与失败分开计", () => {
  const t0 = Date.parse("2026-10-01T00:00:00.000Z");
  const H = 1800_000;
  const rec = (offsetMs: number, over: Partial<RunRecord> = {}): RunRecord => ({
    run_at: new Date(t0 + offsetMs).toISOString(),
    source_id: over.source_id ?? "ubuntu_usn",
    ok: over.ok ?? true,
    fetched: 1,
    parsed: 1,
    merged: 1,
    verdicts: 1,
    fallback_events: 0,
    ...over,
  });
  // 0..5H 每节拍一次（6 次），断档后 20H 再来两次（同一时刻：一次源记录 + 一次心跳）
  const records: RunRecord[] = [
    rec(0), rec(H), rec(2 * H), rec(3 * H), rec(4 * H, { ok: false, error: "503" }), rec(5 * H),
    rec(20 * H),
    rec(20 * H, { degraded_to: "fixture", source_id: "cisa_kev" }),
  ];
  const stats = computeUptime(records, { heartbeat_s: 1800 });
  assert.equal(stats.heartbeats_observed, 7); // 不同 run_at 个数
  assert.equal(stats.heartbeats_expected, 21); // floor(20H/H)+1
  assert.equal(stats.coverage_ratio, 0.3333); // 7/21
  assert.equal(stats.segments.length, 2);
  assert.equal(stats.longest_continuous_ms, 6 * H); // 5H − 0H + 一个节拍
  assert.equal(stats.total_uptime_ms, 7 * H);
  assert.equal(stats.failed_runs, 1);
  assert.equal(stats.degraded_runs, 1);
  assert.equal(stats.failures_by_source["ubuntu_usn"], 1);
  assert.equal(stats.degraded_by_source["cisa_kev"], 1);
});

test("uptime：心跳太稀疏时不许报出 100% 覆盖率（防「手动跑两轮」冒充常驻挂机）", () => {
  const t0 = Date.parse("2026-10-01T00:00:00.000Z");
  const rec = (ms: number): RunRecord => ({
    run_at: new Date(t0 + ms).toISOString(),
    source_id: "ubuntu_usn",
    ok: true,
    fetched: 1,
    parsed: 1,
    merged: 1,
    verdicts: 1,
    fallback_events: 0,
  });
  const sparse = computeUptime([rec(0), rec(9 * 3600_000)], { defaultHeartbeatS: 1800 });
  assert.equal(sparse.heartbeat_source, "insufficient");
  assert.equal(sparse.heartbeat_s, 1800);
  assert.equal(sparse.heartbeats_observed, 2);
  assert.equal(sparse.heartbeats_expected, 19); // floor(9h/30min)+1
  assert.ok(sparse.coverage_ratio < 0.15, `覆盖率应远低于 1，实际 ${sparse.coverage_ratio}`);
  assert.equal(sparse.coverage_reliable, false);
  assert.match(sparse.reliability_note, /不可作为 72h 证据/);
});

test("uptime：常驻密集心跳 → 节拍可推断且覆盖率可信", () => {
  const t0 = Date.parse("2026-10-01T00:00:00.000Z");
  const tick = (i: number): RunRecord => ({
    run_at: new Date(t0 + i * 300_000).toISOString(),
    source_id: "_heartbeat",
    ok: true,
    fetched: 0,
    parsed: 0,
    merged: 0,
    verdicts: 0,
    fallback_events: 0,
    kind: "tick",
  });
  const stats = computeUptime(Array.from({ length: 24 }, (_, i) => tick(i)), { defaultHeartbeatS: 1800 });
  assert.equal(stats.heartbeat_source, "inferred");
  assert.equal(stats.heartbeat_s, 300);
  assert.equal(stats.coverage_reliable, true);
  assert.equal(stats.coverage_ratio, 1);
  assert.equal(stats.segments.length, 1);
});

test("uptime：无窗口参数时窗口取日志首末", () => {
  const t0 = Date.parse("2026-10-01T00:00:00.000Z");
  const rec = (ms: number): RunRecord => ({
    run_at: new Date(t0 + ms).toISOString(),
    source_id: "osv",
    ok: true,
    fetched: 1,
    parsed: 1,
    merged: 1,
    verdicts: 1,
    fallback_events: 0,
  });
  const stats = computeUptime([rec(0), rec(1800_000), rec(3600_000)]);
  assert.equal(stats.window_start, new Date(t0).toISOString());
  assert.equal(stats.window_end, new Date(t0 + 3600_000).toISOString());
  assert.equal(stats.heartbeat_s, 1800); // 由最小间隔推断
  assert.equal(stats.segments.length, 1);
});

test("uptime：读运行日志时坏行跳过不炸整张看板", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-runlog-"));
  try {
    const file = path.join(dir, "runs.jsonl");
    await appendFile(
      file,
      [
        JSON.stringify({ run_at: "2026-10-01T00:00:00.000Z", source_id: "osv", ok: true, fetched: 1, parsed: 1, merged: 1, verdicts: 1, fallback_events: 0 }),
        "{ 这不是 JSON",
        JSON.stringify({ run_at: 42 }),
        "",
      ].join("\n"),
      "utf8",
    );
    const { records, bad_lines } = await readRunLog(file);
    assert.equal(records.length, 1);
    assert.equal(bad_lines, 2);
    const missing = await readRunLog(path.join(dir, "nope.jsonl"));
    assert.deepEqual(missing, { records: [], bad_lines: 0 });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("freshness：水位覆盖 active 源全集——回放中的源不许亮绿灯，本轮没抓的源必须出现", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const pub = new Date(NOW.getTime() - 3600 * 1000).toISOString();
  await bus.publish("intel.items", item({ intel_id: "intel_live", published_at: pub, first_seen_at: NOW.toISOString() }), { trace_id: "tr_t" });
  // ubuntu_usn 本轮是离线回放（payload_ref 指向 fixtures/），osv 本轮根本没产出 raw.doc
  await bus.publish("raw.docs", {
    source_id: "ubuntu_usn",
    source_type: "vendor_advisory",
    external_id: "ubuntu_usn_fixture",
    url: "u",
    fetched_at: NOW.toISOString(),
    content_type: "json",
    payload_ref: "fixtures/sources/usn.sample.json",
  }, { trace_id: "tr_t" });

  const report = await computeFreshnessReport(store, {
    now: NOW,
    activeSourceIds: ["ubuntu_usn", "osv", "nvd_cve"],
  });
  assert.equal(report.watermarks.length, 3, "三个 active 源都要有一行");
  const usn = report.watermarks.find((w) => w.source === "ubuntu_usn")!;
  assert.equal(usn.success, false, "离线回放不能算成功");
  assert.equal(usn.replaying_fixture, true);
  assert.match(usn.error ?? "", /fixture/);
  const osv = report.watermarks.find((w) => w.source === "osv")!;
  assert.equal(osv.skipped_this_run, true);
  assert.equal(osv.success, false);
  assert.match(osv.error ?? "", /未产出 raw\.doc/);
  const nvd = report.watermarks.find((w) => w.source === "nvd_cve")!;
  assert.equal(nvd.skipped_this_run, true, "registry 里在跑但本轮没数据 ⇒ 同样显式标出");
});

test("SLA 常量：6h 阈值口径固定", () => {
  assert.equal(SLA_6H_SECONDS, 21600);
});
