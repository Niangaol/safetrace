/** Deterministic A-01 negative cases. Only memory stores or isolated temporary SQLite. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryEventStore, SqliteEventStore } from "@safetrace/shared";
import type { ThreadCheckpoint } from "@safetrace/shared";
import { runMachine, resumeMachine } from "../src/orchestrator/runtime.js";
import { runTaskGraphViaMachine } from "../src/orchestrator/taskgraph-machine.js";
import { RESUME_VALUE_KEY as KEY, specFingerprint } from "../src/orchestrator/statemachine.js";
import type { MachineSpec, MachineNode } from "../src/orchestrator/statemachine.js";
const C = { backend: "native", interrupts: { enabled: true, node_id: "b" } } as const;
const N = { backend: "native", interrupts: { enabled: false, node_id: null } } as const;
const node = (id: string, run: MachineNode["run"], deps: string[] = []): MachineNode => ({ id, role: "qa", run, deps });
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }

async function race(first: MemoryEventStore | SqliteEventStore, second = first, invoke = false) {
  const gate = deferred(), entered = deferred(); let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", () => {}), node("b", async () => {
    calls++; entered.resolve(); await gate.promise;
  }, ["a"])] };
  if (!invoke) await runMachine(spec, { threadId: "race", store: first, config: C });
  const launch = (store: typeof first) => invoke
    ? runMachine(spec, { threadId: "race", store, config: N })
    : resumeMachine("race", spec, { store, config: C, resumeValue: 1 });
  const running = launch(first);
  await entered.promise;
  try { await assert.rejects(launch(second), /租约占用/); }
  finally { gate.resolve(); }
  assert.equal((await running).ok, true);
  assert.equal(calls, 1);
}
test("checkpoint: concurrent resume has one owner in Memory", () => race(new MemoryEventStore()));
test("checkpoint: concurrent invoke has one owner", () => race(new MemoryEventStore(), undefined, true));
test("checkpoint: concurrent resume across SQLite instances", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-checkpoint-"));
  const a = new SqliteEventStore(join(dir, "test.sqlite"));
  const b = new SqliteEventStore(join(dir, "test.sqlite"));
  try { await race(a, b); } finally { a.close(); b.close(); await rm(dir, { recursive: true, force: true }); }
});

test("checkpoint: graph source, structure, reducers and version are bound", async () => {
  const store = new MemoryEventStore(); let calls = 0;
  const spec: MachineSpec = { version: "v1", nodes: [node("a", s => { s.old = true; }), node("b", () => { calls++; }, ["a"])] };
  await runMachine(spec, { store, threadId: "graph", config: C });
  for (const changed of [
    { ...spec, version: "v2" },
    { ...spec, nodes: [spec.nodes[0]!, node("evil", () => { calls++; }, ["a"])] },
    { ...spec, nodes: [spec.nodes[0]!, node("b", () => { calls += 100; }, ["a"])] },
    { ...spec, reducers: { count: (a: unknown, b: unknown) => [a, b] } },
  ]) await assert.rejects(resumeMachine("graph", changed, { store, config: C, resumeValue: 1 }), /fingerprint/);
  assert.equal(calls, 0);
  assert.equal((await resumeMachine("graph", spec, { store, config: C, resumeValue: 1 })).ok, true);
});

test("checkpoint: resume value goes to recorded node despite config changes", async () => {
  for (const config of [N, { backend: "native", interrupts: { enabled: true, node_id: "c" } } as const]) {
    const store = new MemoryEventStore(); let value: unknown;
    const spec: MachineSpec = { nodes: [node("a", () => {}), node("b", s => { value = s[KEY]; s.answer = 42; }, ["a"]), node("c", () => {}, ["b"])] };
    await runMachine(spec, { store, threadId: "config", config: C });
    const result = await resumeMachine("config", spec, { store, config, resumeValue: 123 });
    assert.equal(value, 123); assert.equal(result.ok, true);
    assert.deepEqual(result.state, { answer: 42 });
    assert.deepEqual((await store.loadThreadCheckpoint("config"))!.state, { answer: 42 });
  }
});

test("checkpoint: legacy fingerprint and malformed progress fail before execution", async () => {
  const store = new MemoryEventStore(); let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", () => {}), node("b", () => { calls++; }, ["a"])] };
  const base: ThreadCheckpoint = { thread_id: "legacy", trace_id: "tr", status: "suspended", executed: ["a"], interrupt_node_id: "b", state: {}, updated_at: new Date().toISOString() };
  await store.saveThreadCheckpoint(base);
  await assert.rejects(resumeMachine("legacy", spec, { store, config: C }), /fingerprint/);
  await store.saveThreadCheckpoint({ ...base, spec_fingerprint: specFingerprint(spec), interrupt_node_id: "ghost" });
  await assert.rejects(resumeMachine("legacy", spec, { store, config: C }), /进度/);
  await store.saveThreadCheckpoint({ ...base, spec_fingerprint: specFingerprint(spec), executed: ["ghost"] });
  await assert.rejects(resumeMachine("legacy", spec, { store, config: C }), /进度/);
  assert.equal(calls, 0);
});

test("checkpoint: reserved initial state and declared writes rejected", async () => {
  const spec: MachineSpec = { nodes: [node("a", () => {})] };
  await assert.rejects(runMachine(spec, { config: N, initialState: { [KEY]: "business" } }), /保留键/);
  await assert.rejects(runMachine({ nodes: [{ ...spec.nodes[0]!, writes: [KEY] }] }, { config: N }), /保留键/);
});
test("checkpoint: dynamic reserved writes cannot degrade into a poisoned suspension", async () => {
  for (const mutate of [
    (s: Record<string, unknown>) => { s[KEY] = 1; },
    (s: Record<string, unknown>) => { Object.defineProperty(s, KEY, { value: 1 }); },
  ]) {
    const store = new MemoryEventStore();
    const spec: MachineSpec = { nodes: [{ ...node("a", mutate), on_fail: "degrade" }, node("b", () => {}, ["a"])] };
    const result = await runMachine(spec, { store, threadId: "reserved", config: C });
    assert.equal(result.ok, false); assert.match(result.failed!.error, /保留键/);
    assert.equal((await store.loadThreadCheckpoint("reserved"))!.status, "failed");
    assert.equal(KEY in result.state, false);
  }
});

test("checkpoint: equal incoming values still run reducers", async () => {
  const spec: MachineSpec = { nodes: [{ ...node("a", s => { s.n = 1; }), writes: ["n"] },
    { ...node("b", s => { s.n = 1; }, ["a"]), writes: ["n"] }],
    reducers: { n: (a, b) => Number(a) + Number(b) } };
  const result = await runMachine(spec, { config: N });
  assert.equal(result.state.n, 2);
});
test("checkpoint: reducers receive immutable previous snapshot for in-place writes", async () => {
  const spec: MachineSpec = { nodes: [{ ...node("a", s => { s.hits = ["a"]; }), writes: ["hits"] },
    { ...node("b", s => { (s.hits as string[]).push("b"); }, ["a"]), writes: ["hits"] }],
    reducers: { hits: (a, b) => ({ previous: a, incoming: b }) } };
  const result = await runMachine(spec, { config: N });
  assert.deepEqual(result.state.hits, { previous: ["a"], incoming: ["a", "b"] });
});
test("checkpoint: reducer errors follow failure policy and roll back partial state", async () => {
  const spec: MachineSpec = { nodes: [node("a", s => { s.n = 1; }),
    { ...node("b", s => { s.n = 2; s.partial = true; }, ["a"]), writes: ["n"], on_fail: "degrade" },
    node("c", s => { assert.equal(s.partial, undefined); assert.equal(s.n, 1); }, ["b"])],
    reducers: { n: () => { throw Error("reducer failure"); } } };
  const result = await runMachine(spec, { config: N });
  assert.equal(result.ok, true); assert.deepEqual(result.degraded_nodes, ["b→degraded"]);
  assert.deepEqual(result.state, { n: 1 });
});

test("checkpoint: aborted resume persists completed progress and retry skips it", async () => {
  const store = new MemoryEventStore(); let bCalls = 0, fail = true;
  const spec: MachineSpec = { nodes: [node("a", () => {}), node("b", s => { bCalls++; s.b = "done"; }, ["a"]),
    node("c", s => { s.partial = true; if (fail) throw Error("abort"); s.answer = 42; }, ["b"])] };
  await runMachine(spec, { store, threadId: "abort", config: C });
  const failed = await resumeMachine("abort", spec, { store, config: C, resumeValue: 1 });
  assert.equal(failed.ok, false);
  const cp = (await store.loadThreadCheckpoint("abort"))!;
  assert.equal(cp.status, "failed"); assert.deepEqual(cp.executed, ["a", "b"]);
  assert.deepEqual(cp.state, { b: "done" });
  await assert.rejects(runMachine(spec, { store, threadId: "abort", config: N }), /已存在/);
  fail = false;
  const retried = await resumeMachine("abort", spec, { store, config: N });
  assert.equal(retried.ok, true); assert.equal(bCalls, 1);
});

class FaultStore extends MemoryEventStore {
  failAt = 0; saves = 0;
  override async saveThreadCheckpoint(cp: ThreadCheckpoint) {
    this.saves++;
    if (this.saves === this.failAt) throw Error("checkpoint disk fail");
    await super.saveThreadCheckpoint(cp);
  }
}
test("checkpoint: initial save failure executes no node and retains lease", async () => {
  const store = new FaultStore(); store.failAt = 1; let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", () => { calls++; })] };
  await assert.rejects(runMachine(spec, { store, threadId: "disk", config: N }), /disk fail/);
  store.failAt = 0;
  await assert.rejects(runMachine(spec, { store, threadId: "disk", config: N }), /租约占用/);
  assert.equal(calls, 0);
});
test("checkpoint: step save failure stops downstream and blocks retries", async () => {
  const store = new FaultStore(); store.failAt = 2; let calls = 0, downstream = 0;
  const spec: MachineSpec = { nodes: [node("a", () => { calls++; }), node("b", () => { downstream++; }, ["a"])] };
  await assert.rejects(runMachine(spec, { store, threadId: "disk", config: N }), /disk fail/);
  store.failAt = 0;
  await assert.rejects(runMachine(spec, { store, threadId: "disk", config: N }), /租约占用/);
  await assert.rejects(resumeMachine("disk", spec, { store, config: N }), /租约占用/);
  assert.equal(calls, 1); assert.equal(downstream, 0);
});
test("checkpoint: completed save failure cannot replay finished side effects", async () => {
  const store = new FaultStore(); store.failAt = 3; let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", s => { calls++; s.answer = 42; })] };
  await assert.rejects(runMachine(spec, { store, threadId: "disk", config: N }), /disk fail/);
  assert.deepEqual((await store.loadThreadCheckpoint("disk"))!.state, { answer: 42 });
  await assert.rejects(resumeMachine("disk", spec, { store, config: N }), /租约占用/);
  assert.equal(calls, 1);
});

test("checkpoint: TaskGraph missing resume rejects and actual suspension restores value", async () => {
  const store = new MemoryEventStore(); let calls = 0, value: unknown;
  const graph = { nodes: [{ id: "a", role: "monitor" as const, run: () => {} },
    { id: "b", role: "qa" as const, deps: ["a"], run: (s?: Record<string, unknown>) => { calls++; value = s?.[KEY]; } }] };
  await assert.rejects(runTaskGraphViaMachine(graph, { threadStore: store, threadId: "missing", resumeValue: 1 }), /不存在/);
  await assert.rejects(runTaskGraphViaMachine(graph, { resumeValue: 1 }), /store/);
  const first = await runTaskGraphViaMachine(graph, { threadStore: store, threadId: "graph", config: C });
  assert.equal(first.interrupted, true); assert.equal(calls, 0);
  const result = await runTaskGraphViaMachine(graph, { threadStore: store, threadId: "graph", config: N, resumeValue: 123 });
  assert.equal(result.ok, true); assert.equal(calls, 1); assert.equal(value, 123);
});

test("checkpoint: invalid interrupt config rejects before side effects", async () => {
  let calls = 0;
  await assert.rejects(runMachine({ nodes: [node("a", () => { calls++; })] }, { config: C }), /interrupt 节点不存在/);
  assert.equal(calls, 0);
});

test("checkpoint: release failure retains claim after durable completion", async () => {
  class ReleaseFault extends MemoryEventStore {
    override async releaseThreadLease(): Promise<boolean> { throw Error("release failure"); }
  }
  const store = new ReleaseFault(); let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", () => { calls++; })] };
  await assert.rejects(runMachine(spec, { store, threadId: "release", config: N }), /release failure/);
  assert.equal((await store.loadThreadCheckpoint("release"))!.status, "completed");
  await assert.rejects(runMachine(spec, { store, threadId: "release", config: N }), /租约占用/);
  assert.equal(calls, 1);
});

test("checkpoint: SQLite fault survives reopen and blocks replay", async () => {
  class DiskFault extends SqliteEventStore {
    override async saveThreadCheckpoint(cp: ThreadCheckpoint) {
      if (cp.status === "completed") throw Error("disk failure");
      await super.saveThreadCheckpoint(cp);
    }
  }
  const dir = await mkdtemp(join(tmpdir(), "safetrace-checkpoint-fault-"));
  const path = join(dir, "test.sqlite");
  const first = new DiskFault(path); let calls = 0;
  const spec: MachineSpec = { nodes: [node("a", s => { calls++; s.answer = 42; })] };
  try {
    await assert.rejects(runMachine(spec, { store: first, threadId: "crash", config: N }), /disk failure/);
  } finally { first.close(); }
  const reopened = new SqliteEventStore(path);
  try {
    const cp = (await reopened.loadThreadCheckpoint("crash"))!;
    assert.equal(cp.status, "running"); assert.deepEqual(cp.state, { answer: 42 });
    await assert.rejects(resumeMachine("crash", spec, { store: reopened, config: N }), /租约占用/);
    await assert.rejects(runMachine(spec, { store: reopened, threadId: "crash", config: N }), /租约占用/);
    assert.equal(calls, 1);
  } finally { reopened.close(); await rm(dir, { recursive: true, force: true }); }
});

test("checkpoint: removing lease alone cannot resume uncertain running progress", async () => {
  class CaptureFault extends FaultStore {
    token = "";
    override async acquireThreadLease(id: string, token: string) { this.token = token; return super.acquireThreadLease(id, token); }
  }
  const store = new CaptureFault(); store.failAt = 2;
  const spec: MachineSpec = { nodes: [node("a", () => {})] };
  await assert.rejects(runMachine(spec, { store, threadId: "audit", config: N }), /disk fail/);
  assert.equal(await store.releaseThreadLease("audit", store.token), true);
  await assert.rejects(resumeMachine("audit", spec, { store, config: N }), /status=running/);
});

test("checkpoint: uncloneable node output is a fatal snapshot error, not degrade", async () => {
  const store = new MemoryEventStore(); let calls = 0, downstream = 0;
  const spec: MachineSpec = { nodes: [{ ...node("a", s => { calls++; s.invalid = () => 1; }), on_fail: "degrade" },
    node("b", () => { downstream++; }, ["a"])] };
  await assert.rejects(runMachine(spec, { store, threadId: "snapshot", config: N }), /clone/);
  await assert.rejects(resumeMachine("snapshot", spec, { store, config: N }), /租约占用/);
  assert.equal(calls, 1); assert.equal(downstream, 0);
});
