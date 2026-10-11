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
import { MemorySourceScheduleStore, SqliteSourceScheduleStore } from "../src/schedule-state.js";
import type { IngestRunResult, RunIngestOnceOpts } from "../src/pipeline.js";
import { fetchNvd } from "../src/sources/nvd.js";
import { parseNvd } from "../src/adapters/nvd.js";

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
test("scheduler：从持久 intel.items 给 OSV 传 CVE seed，且不依赖本轮 KEV runner", async () => {
  const { makeEnvelope } = await import("@safetrace/shared");
  const store = new MemoryEventStore();
  await store.append(makeEnvelope("intel.items", { intel_id: "intel_seed", cve_ids: ["CVE-2026-76504"], source_ids: ["cisa_kev"], published_at: "2026-09-30T00:00:00.000Z", title: "seed" }));
  assert.deepEqual((await store.read<{ cve_ids: string[] }>("intel.items"))[0]?.payload.cve_ids, ["CVE-2026-76504"]);
  const originalFetch = globalThis.fetch;
  const originalOffline = process.env.OFFLINE_FIXTURES;
  const urls: string[] = [];
  process.env.OFFLINE_FIXTURES = "false";
  globalThis.fetch = (async (input: string | URL | Request) => {
    urls.push(String(input));
    return new Response(JSON.stringify({ id: "CVE-2026-76504", aliases: [], summary: "Test advisory", details: "Live lookup probe", published: "2026-09-30T00:00:00Z", modified: "2026-09-30T00:00:00Z", affected: [] }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const clock = makeClock(T0, DAY);
    const summary = await runIngestScheduler({ store, offline: false, sourceIds: ["osv"], maxCycles: 1, nowMs: clock.nowMs, sleep: clock.sleep, runLogPath: null });
    assert.ok(urls.some((url) => url.includes("api.osv.dev/v1/vulns/CVE-2026-76504")), JSON.stringify({ urls, records: summary.records }));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalOffline === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = originalOffline;
  }
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
const emptyResult = (): IngestRunResult => ({ trace_id: "test", lineage_parent_by_intel_id: {}, causation_by_intel_id: {}, fetched: [], parsed: [], merged: [], verdicts: [], fallbackEvents: [] });
async function liveResult(): Promise<IngestRunResult> {
  // Offline fixture is explicitly reused only as a mock HTTP response body in this unit test.
  const fixture = (await fetchNvd({ offline: true }))!;
  const raw = { ...fixture, external_id: "mock-live-http" };
  const parsed = (await parseNvd(raw)).items;
  return { ...emptyResult(), fetched: [raw], parsed, merged: parsed };
}

test("scheduler: slow source cannot block later fast-source poll or immediate handoff; same source never overlaps", async () => {
  const slow = deferred<IngestRunResult>();
  const first = deferred<void>(), second = deferred<void>();
  let t = T0, wakes = 0, slowCalls = 0, fastCalls = 0, active = 0, peak = 0;
  const handed: string[] = [];
  const summary = await runIngestScheduler({ store: new MemoryEventStore(), sourceIds: ["nvd_cve", "ubuntu_usn"], maxCycles: 3, runLogPath: null,
    nowMs: () => t,
    runSource: async id => {
      active++; peak = Math.max(peak, active);
      if (id === "nvd_cve") { slowCalls++; const result = await slow.promise; active--; return result; }
      fastCalls++; active--; return emptyResult();
    },
    onIngestResult: id => { handed.push(id); },
    onRecord: r => { if (r.source_id === "ubuntu_usn") { if (fastCalls === 1) first.resolve(); else second.resolve(); } },
    sleep: async () => {
      if (wakes++ === 0) { await first.promise; assert.deepEqual(handed, ["ubuntu_usn"]); }
      else { await second.promise; assert.equal(slowCalls, 1); assert.equal(fastCalls, 2); slow.resolve(emptyResult()); }
      // Record callback occurs just before the job reservation is released.
      await new Promise<void>(resolve => setImmediate(resolve));
      t += 1800_000;
    },
  });
  assert.equal(slowCalls, 1);
  assert.equal(fastCalls, 3);
  assert.equal(peak, 2);
  assert.equal(summary.records.length, 4);
});

test("scheduler: persistent restart respects official interval and NVD overlap covers downtime", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sched-restart-"));
  const filename = path.join(dir, "state.sqlite");
  let t = T0, calls = 0;
  const result = await liveResult();
  const windows: RunIngestOnceOpts[] = [];
  const options = { store: new MemoryEventStore(), sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => t,
    runSource: async (_id: string, opts: RunIngestOnceOpts) => { calls++; windows.push(opts); return result; } };
  try {
    const state1 = new SqliteSourceScheduleStore(filename);
    await runIngestScheduler({ ...options, scheduleState: state1 });
    assert.equal((await state1.get("nvd_cve"))?.last_success_at, new Date(T0).toISOString());
    state1.close();
    const state2 = new SqliteSourceScheduleStore(filename);
    t += 1000;
    await runIngestScheduler({ ...options, scheduleState: state2 });
    assert.equal(calls, 1, "restart must not repoll immediately");
    t += 10 * DAY;
    await runIngestScheduler({ ...options, scheduleState: state2, overlapMs: 3600_000 });
    const first = windows[0]!.sourceOptions!.nvd_cve!;
    assert.equal(Date.parse((first.pubWindow as {start: string}).start), T0 - 48 * 3600_000, "boot never scans all history");
    const catchup = windows[1]!.sourceOptions!.nvd_cve!;
    for (const name of ["window", "pubWindow"]) {
      const window = catchup[name] as { start: string; end: string };
      assert.equal(Date.parse(window.start), T0 - 3600_000);
      assert.equal(Date.parse(window.end), t);
    }
    state2.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("scheduler: persisted failure backoff never bypasses official interval", async () => {
  const state = new MemorySourceScheduleStore();
  let t = T0, calls = 0;
  const options = { store: new MemoryEventStore(), scheduleState: state, sourceIds: ["ubuntu_usn"], maxCycles: 1, runLogPath: null, nowMs: () => t,
    failureBackoffMs: (n: number) => n * 3600_000,
    runSource: async () => { calls++; throw new Error("mock failure"); } };
  await runIngestScheduler(options);
  assert.equal((await state.get("ubuntu_usn"))?.next_due_at, new Date(T0 + 3600_000).toISOString());
  t += 1800_000; await runIngestScheduler(options); assert.equal(calls, 1);
  t += 1800_000; await runIngestScheduler(options);
  const failed = (await state.get("ubuntu_usn"))!;
  assert.equal(failed.status, "failed"); assert.equal(failed.consecutive_failures, 2); assert.equal(failed.last_success_at, null);
  assert.equal(Date.parse(failed.next_due_at), t + 7200_000);
});

test("scheduler: fixture, no_data, partial, truncated and handoff failures never advance coverage", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sched-status-"));
  const { writeFile } = await import("node:fs/promises");
  try {
    const complete = await liveResult();
    for (const status of ["fixture", "no_data", "partial", "truncated", "failed"] as const) {
      const state = new MemorySourceScheduleStore();
      const cursor = new Date(T0 - DAY).toISOString();
      await state.set({ source_id: "nvd_cve", last_attempt_at: cursor, last_success_at: cursor, next_due_at: cursor, consecutive_failures: 0, status: "complete" });
      let result = complete;
      if (status === "fixture") result = { ...complete, degraded_to: "fixture" };
      if (status === "no_data") result = emptyResult();
      if (status === "partial" || status === "truncated") {
        const payload_ref = path.join(dir, status + ".json");
        await writeFile(payload_ref, JSON.stringify({ [status]: true }));
        result = { ...complete, fetched: [{ ...complete.fetched[0]!, payload_ref }] };
      }
      const summary = await runIngestScheduler({ store: new MemoryEventStore(), scheduleState: state, sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => T0,
        runSource: async () => result,
        onIngestResult: status === "failed" ? async () => { throw new Error("handoff queue unavailable"); } : undefined });
      assert.equal((await state.get("nvd_cve"))?.last_success_at, cursor, status);
      assert.equal(summary.records[0]?.status, status);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("scheduler: cursor is query-end/start time, never slow request finish time", async () => {
  const state = new MemorySourceScheduleStore();
  let t = T0;
  const result = await liveResult();
  let finished = "";
  await runIngestScheduler({ store: new MemoryEventStore(), scheduleState: state, sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => t,
    runSource: async () => { t += 3600_000; return result; }, onIngestResult: (_id, _result, at) => { finished = at; } });
  assert.equal(finished, new Date(T0 + 3600_000).toISOString());
  assert.equal((await state.get("nvd_cve"))?.last_success_at, new Date(T0).toISOString());
});

test("scheduler: successful empty dual NVD windows advance coverage but retain no_data status", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sched-empty-"));
  const { writeFile } = await import("node:fs/promises");
  try {
    const payload_ref = path.join(dir, "empty.json");
    await writeFile(payload_ref, JSON.stringify({ coverage_complete: true, vulnerabilities: [], windows: ["pubDate", "lastMod"].map(kind => ({ kind, failed_pages: 0, truncated: false, empty: true })) }));
    const sample = (await liveResult()).fetched[0]!;
    const state = new MemorySourceScheduleStore();
    const summary = await runIngestScheduler({ store: new MemoryEventStore(), scheduleState: state, sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => T0,
      runSource: async () => ({ ...emptyResult(), fetched: [{ ...sample, payload_ref }] }) });
    assert.equal(summary.records[0]?.status, "no_data");
    assert.equal(summary.records[0]?.coverage_complete, true);
    assert.equal((await state.get("nvd_cve"))?.last_success_at, new Date(T0).toISOString());
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("scheduler: offline replay namespace cannot suppress live polling or advance its cursor", async () => {
  const state = new MemorySourceScheduleStore();
  let liveCalls = 0;
  const options = { store: new MemoryEventStore(), scheduleState: state, sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => T0 };
  await runIngestScheduler({ ...options, offline: true, runSource: async () => emptyResult() });
  assert.equal(await state.get("nvd_cve"), undefined);
  assert.equal((await state.get("offline:nvd_cve"))?.last_success_at, null);
  await runIngestScheduler({ ...options, runSource: async () => { liveCalls++; return emptyResult(); } });
  assert.equal(liveCalls, 1);
  assert.equal((await state.get("nvd_cve"))?.last_success_at, null);
});

test("scheduler: owned event store uses companion metadata DB only inside test temp path", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "sched-owned-"));
  const filename = path.join(dir, "events.sqlite");
  const previous = process.env.SQLITE_PATH;
  process.env.SQLITE_PATH = filename;
  try {
    await runIngestScheduler({ sourceIds: ["nvd_cve"], maxCycles: 1, runLogPath: null, nowMs: () => T0, runSource: async () => emptyResult() });
    const state = new SqliteSourceScheduleStore(filename + ".schedule.sqlite");
    assert.equal((await state.get("nvd_cve"))?.status, "no_data");
    state.close();
  } finally {
    if (previous === undefined) delete process.env.SQLITE_PATH; else process.env.SQLITE_PATH = previous;
    await rm(dir, { recursive: true, force: true });
  }
});
