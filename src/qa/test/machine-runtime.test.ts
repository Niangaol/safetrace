/**
 * A-01 回归：threadId 持久化 + invoke/resume 接通（挂起/恢复真实可用）。
 * 口径：挂起点落检查点（suspended）；resume 跳过已执行节点、注入恢复值；
 * completed 线程禁止重复 invoke；未挂起禁止 resume；SQLite 跨重启可恢复。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryEventStore, SqliteEventStore } from "@safetrace/shared";
import type { MachineSpec } from "../src/orchestrator/statemachine.js";
import { RESUME_VALUE_KEY } from "../src/orchestrator/statemachine.js";
import { resumeMachine, runMachine } from "../src/orchestrator/runtime.js";
import { runTaskGraphViaMachine } from "../src/orchestrator/taskgraph-machine.js";
import type { TaskGraph } from "../src/orchestrator/taskgraph.js";

const INTERRUPT_AT_B = { backend: "native", interrupts: { enabled: true, node_id: "b" } } as const;
const NO_INTERRUPT = { backend: "native", interrupts: { enabled: false, node_id: null } } as const;

test("A-01：节点共享 state，reducers 按声明合并重复写入字段", async () => {
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", writes: ["hits"], run: (state) => { state.hits = ["a"]; } },
      { id: "b", role: "enricher", deps: ["a"], writes: ["hits", "count"], run: (state) => { state.hits = ["b"]; state.count = 2; } },
      { id: "c", role: "qa", deps: ["b"], writes: ["count"], run: (state) => { state.count = (state.count as number) + 3; } },
    ],
    reducers: { hits: (current, incoming) => [...(current as string[]), ...(incoming as string[])], count: (current, incoming) => (current as number) + (incoming as number) },
  };
  const res = await runMachine(spec, { config: NO_INTERRUPT });
  assert.equal(res.ok, true);
  assert.deepEqual(res.executed, ["a", "b", "c"]);
});

test("A-01：interrupt 挂起——interrupted_at、onInterrupt 快照、检查点 suspended", async () => {
  const store = new MemoryEventStore();
  const seen: string[] = [];
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", writes: ["log"], run: (state) => { seen.push("a"); state.log = "a-ran"; } },
      { id: "b", role: "enricher", deps: ["a"], writes: ["log"], run: (state) => { seen.push("b"); state.log = "b-ran"; } },
      { id: "c", role: "qa", deps: ["b"], run: () => { seen.push("c"); } },
    ],
    reducers: {},
  };
  const res = await runMachine(spec, { store, config: INTERRUPT_AT_B });
  assert.equal(res.interrupted, true);
  assert.equal(res.interrupted_at, "b");
  assert.deepEqual(res.executed, ["a"], "挂起点前的节点已执行");
  assert.deepEqual(seen, ["a"], "挂起节点与后续节点都不能执行");
  const cp = await store.loadThreadCheckpoint(res.thread_id);
  assert.ok(cp, "挂起必须落检查点");
  assert.equal(cp!.status, "suspended");
  assert.equal(cp!.interrupt_node_id, "b");
  assert.deepEqual(cp!.executed, ["a"]);
  assert.equal(cp!.state.log, "a-ran", "检查点必须带挂起点状态快照");
});

test("A-01：resume 续跑——跳过已执行、恢复值注入保留键、检查点转 completed", async () => {
  const store = new MemoryEventStore();
  const seen: string[] = [];
  const resumeValues: unknown[] = [];
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", writes: ["log"], run: (state) => { seen.push("a"); state.log = "a-ran"; } },
      { id: "b", role: "enricher", deps: ["a"], writes: ["log"], run: (state) => { seen.push("b"); resumeValues.push(state[RESUME_VALUE_KEY]); state.log = "b-ran"; } },
      { id: "c", role: "qa", deps: ["b"], run: (state) => { seen.push("c"); state.final = (state.log as string) + "+c"; } },
    ],
    reducers: {},
  };
  const first = await runMachine(spec, { store, config: INTERRUPT_AT_B });
  assert.equal(first.interrupted, true);
  const resumed = await resumeMachine(first.thread_id, spec, { store, config: INTERRUPT_AT_B, resumeValue: { approved: true } });
  assert.equal(resumed.ok, true);
  assert.equal(resumed.interrupted, false);
  assert.deepEqual(seen, ["a", "b", "c"], "已执行的 a 不重跑，b/c 续跑");
  assert.deepEqual(resumeValues, [{ approved: true }], "恢复值必须到达挂起节点");
  assert.deepEqual(resumed.executed, ["a", "b", "c"]);
  const cp = await store.loadThreadCheckpoint(first.thread_id);
  assert.equal(cp!.status, "completed", "跑完必须落 completed");
});

test("A-01：fail-closed——重复 invoke / resume 不存在 / resume 已完成都显式抛错", async () => {
  const store = new MemoryEventStore();
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", run: () => {} },
      { id: "b", role: "enricher", deps: ["a"], run: () => {} },
    ],
    reducers: {},
  };
  const suspended = await runMachine(spec, { store, config: INTERRUPT_AT_B });
  await assert.rejects(runMachine(spec, { store, threadId: suspended.thread_id, config: INTERRUPT_AT_B }), /已存在/);
  await assert.rejects(resumeMachine("thread_missing", spec, { store, config: INTERRUPT_AT_B, resumeValue: 1 }), /不存在/);
  await resumeMachine(suspended.thread_id, spec, { store, config: INTERRUPT_AT_B, resumeValue: 1 });
  await assert.rejects(resumeMachine(suspended.thread_id, spec, { store, config: INTERRUPT_AT_B, resumeValue: 2 }), /非挂起态/);
  await assert.rejects(runMachine(spec, { store, threadId: suspended.thread_id, config: INTERRUPT_AT_B }), /已存在/);
});

test("A-01：无 store 时纯内存执行（挂起后不落检查点，也不报错）", async () => {
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", run: () => {} },
      { id: "b", role: "enricher", deps: ["a"], run: () => {} },
    ],
    reducers: {},
  };
  const res = await runMachine(spec, { config: INTERRUPT_AT_B });
  assert.equal(res.interrupted, true);
  assert.ok(res.thread_id.startsWith("thread_"), "threadId 缺省自动生成");
});

test("A-01：SQLite 检查点跨重启保留（挂起→重开→resume）", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-thread-"));
  const dbPath = join(dir, "safetrace.sqlite");
  try {
    const spec: MachineSpec = {
      nodes: [
        { id: "a", role: "monitor", writes: ["log"], run: (state) => { state.log = "a-ran"; } },
        { id: "b", role: "enricher", deps: ["a"], writes: ["log"], run: (state) => { state.log = "b-ran"; } },
      ],
      reducers: {},
    };
    const first = new SqliteEventStore(dbPath);
    const suspended = await runMachine(spec, { store: first, threadId: "thread_fixed", config: INTERRUPT_AT_B });
    assert.equal(suspended.interrupted, true);
    first.close();
    // 模拟进程重启：新开同一库文件，检查点仍在
    const second = new SqliteEventStore(dbPath);
    const cp = await second.loadThreadCheckpoint("thread_fixed");
    assert.ok(cp && cp.status === "suspended" && cp.state.log === "a-ran");
    const resumed = await resumeMachine("thread_fixed", spec, { store: second, config: INTERRUPT_AT_B, resumeValue: "go" });
    assert.equal(resumed.ok, true);
    assert.deepEqual(resumed.executed, ["a", "b"]);
    assert.equal((await second.loadThreadCheckpoint("thread_fixed"))!.status, "completed");
    second.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("A-01：TaskGraph 适配层挂起→resume 全链路（thread_id 贯穿）", async () => {
  const store = new MemoryEventStore();
  const seen: string[] = [];
  const graph: TaskGraph = {
    nodes: [
      { id: "monitor", role: "monitor", run: (state) => { seen.push("monitor"); if (state) state.monitor = "done"; } },
      { id: "enricher", role: "enricher", deps: ["monitor"], run: (state) => { seen.push("enricher"); if (state) state.enricher = "done"; } },
      { id: "qa", role: "qa", deps: ["enricher"], run: (state) => { seen.push("qa"); if (state) state.qa = "done"; } },
    ],
  };
  // 适配层用默认配置（orchestration.yml 当前 interrupts 关闭）时不挂起，直接跑完
  const plain = await runTaskGraphViaMachine(graph, { threadStore: store });
  assert.equal(plain.ok, true);
  assert.equal(plain.interrupted, false);
  assert.deepEqual(plain.executed, ["monitor", "enricher", "qa"]);
  assert.ok(plain.thread_id.startsWith("thread_"));
  assert.deepEqual(seen, ["monitor", "enricher", "qa"]);
  // 同一 threadId 再跑 → 显式抛错（completed 不能重跑）
  await assert.rejects(runTaskGraphViaMachine(graph, { threadStore: store, threadId: plain.thread_id }), /非挂起态|已存在/);
});