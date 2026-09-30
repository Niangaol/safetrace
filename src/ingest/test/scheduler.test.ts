/** E-07 调度器单测：注入时钟与 sleep，验证「按源到点、失败隔离、日志落盘、优雅停止」。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { MemoryEventStore } from "@safetrace/shared";
import { runIngestScheduler } from "../src/scheduler.js";
import { readRunLog } from "../src/uptime.js";
import { activeSources } from "../src/registry.js";

/** 假时钟：每次 sleep 前进 stepMs，让「按 poll_interval 到点」可以在毫秒内被验证。 */
function makeClock(startMs: number, stepMs: number): { nowMs: () => number; sleep: () => Promise<void> } {
  let t = startMs;
  return { nowMs: () => t, sleep: async () => { t += stepMs; } };
}

const T0 = Date.parse("2026-10-01T00:00:00.000Z");
const DAY = 24 * 3600 * 1000;

test("scheduler：每轮到点源各执行一次，事件与降级都落进同一 store", async () => {
  const store = new MemoryEventStore();
  const clock = makeClock(T0, DAY); // 每轮前进一天 ⇒ 所有源每轮都到点
  const seen: string[] = [];
  const summary = await runIngestScheduler({
    store,
    offline: true,
    maxCycles: 2,
    checkIntervalMs: DAY,
    nowMs: clock.nowMs,
    sleep: clock.sleep,
    runLogPath: null,
    onRecord: (r) => { seen.push(r.source_id); },
  });
  const active = activeSources().map((s) => s.source_id);
  assert.equal(summary.cycles, 2);
  assert.equal(summary.records.length, active.length * 2); // 五源两轮
  assert.equal(seen.length, active.length * 2);
  for (const r of summary.records) {
    assert.equal(r.ok, true, r.source_id + " 离线回放不应失败");
    assert.equal(r.degraded_to, "fixture"); // 红线：降级在运行记录里显式可见
    assert.equal(r.fallback_events, 1);
  }
  assert.deepEqual([...new Set(summary.records.map((r) => r.source_id))].sort(), [...active].sort());
  const rawDocs = await store.read("raw.docs");
  assert.equal(rawDocs.length, active.length * 2); // 两轮各写一条 raw.doc
});

test("scheduler：只调度指定源（sourceIds 过滤）", async () => {
  const store = new MemoryEventStore();
  const clock = makeClock(T0, DAY);
  const summary = await runIngestScheduler({
    store,
    offline: true,
    sourceIds: ["ubuntu_usn"],
    maxCycles: 3,
    nowMs: clock.nowMs,
    sleep: clock.sleep,
    runLogPath: null,
  });
  assert.equal(summary.records.length, 3);
  assert.ok(summary.records.every((r) => r.source_id === "ubuntu_usn"));
});

test("scheduler：shouldStop 在轮次之间生效（优雅退出，不留半个请求）", async () => {
  const store = new MemoryEventStore();
  let wakes = 0;
  const summary = await runIngestScheduler({
    store,
    offline: true,
    sleep: async () => { wakes += 1; },
    shouldStop: () => wakes >= 2,
    runLogPath: null,
  });
  assert.equal(summary.cycles, 2);
});

test("scheduler：未到 poll_interval 的源不重复抓（1800s 与 7200s 到点次数不同）", async () => {
  const store = new MemoryEventStore();
  const clock = makeClock(T0, 1800_000); // 每轮前进 30 分钟
  const summary = await runIngestScheduler({
    store,
    offline: true,
    sourceIds: ["ubuntu_usn", "nvd_cve"],
    maxCycles: 5,
    nowMs: clock.nowMs,
    sleep: clock.sleep,
    runLogPath: null,
  });
  const usnRuns = summary.records.filter((r) => r.source_id === "ubuntu_usn").length;
  const nvdRuns = summary.records.filter((r) => r.source_id === "nvd_cve").length;
  assert.equal(usnRuns, 5); // poll_interval_s=1800 ⇒ 每轮都到点
  assert.equal(nvdRuns, 2); // poll_interval_s=7200 ⇒ 只在第 1、4 轮到点
});

test("scheduler：runLogPath 落盘为 JSONL，可被 uptime.readRunLog 读回", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-sched-"));
  try {
    const file = path.join(dir, "runs.jsonl");
    const store = new MemoryEventStore();
    const clock = makeClock(T0, DAY);
    await runIngestScheduler({
      store,
      offline: true,
      sourceIds: ["osv"],
      maxCycles: 2,
      nowMs: clock.nowMs,
      sleep: clock.sleep,
      runLogPath: file,
    });
    const text = await readFile(file, "utf8");
    const lines = text.trim().split(/\r?\n/);
    // 每轮 1 条源记录 + 1 条进程存活心跳 ⇒ 两轮 4 行
    assert.equal(lines.length, 4);
    const { records, bad_lines } = await readRunLog(file);
    assert.equal(bad_lines, 0);
    assert.equal(records.length, 4);
    const sources = records.filter((r) => r.kind !== "tick");
    const ticks = records.filter((r) => r.kind === "tick");
    assert.equal(sources.length, 2);
    assert.equal(ticks.length, 2);
    assert.equal(sources[0]!.source_id, "osv");
    assert.equal(ticks[0]!.source_id, "_heartbeat");
    assert.equal(sources[0]!.run_at, new Date(T0).toISOString());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
