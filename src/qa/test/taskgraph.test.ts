import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { AGENT_ROLES } from "../src/orchestrator/roles.js";
import { runTaskGraph } from "../src/orchestrator/taskgraph.js";
import type { TaskGraph } from "../src/orchestrator/taskgraph.js";

test("roles：四角色齐备且独占主题无交叉", () => {
  assert.deepEqual(Object.keys(AGENT_ROLES).sort(), ["enricher", "monitor", "qa", "selfheal"]);
  const all: string[] = [];
  for (const role of Object.values(AGENT_ROLES)) {
    assert.ok(role.duties.length >= 3, role.name + " 至少三条职责");
    assert.ok(role.tools.length >= 3, role.name + " 工具白名单至少三项");
    all.push(...role.exclusive_topics);
  }
  assert.equal(new Set(all).size, all.length, "独占主题不得跨角色重复");
  assert.ok(all.includes("qa.queries"));
  assert.ok(all.includes("qa.answers"));
  assert.ok(all.includes("fallback.events"));
});

test("taskgraph：degrade 节点登记 FallbackEvent 并继续", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const ran: string[] = [];
  const graph: TaskGraph = {
    nodes: [
      { id: "n1", role: "qa", run: () => { ran.push("n1"); } },
      { id: "n2", role: "qa", run: () => { ran.push("n2"); throw new Error("boom"); }, on_fail: "degrade" },
      { id: "n3", role: "qa", run: () => { ran.push("n3"); } },
    ],
  };
  const r = await runTaskGraph(graph, { bus, traceId: "tr_tg" });
  assert.equal(r.ok, true);
  assert.deepEqual(r.executed, ["n1", "n2", "n3"]);
  assert.deepEqual(ran, ["n1", "n2", "n3"]);
  assert.equal(r.degraded_nodes.length, 1);
  assert.equal(r.degraded_nodes[0], "n2→task:n2");
  assert.equal(r.failed, null);

  const events = await store.read<{
    layer: string; degraded_of: string; user_visible: boolean; degraded_state: { label: string }; trace_id: string;
  }>("fallback.events");
  assert.equal(events.length, 1, "降级必须登记 FallbackEvent 入总线");
  assert.equal(events[0]!.payload.layer, "L1");
  assert.equal(events[0]!.payload.degraded_of, "task:n2");
  assert.equal(events[0]!.payload.user_visible, true);
  assert.ok(events[0]!.payload.degraded_state.label.length > 0);
  assert.equal(events[0]!.trace_id, "tr_tg");
});

test("taskgraph：abort 节点停止并返回失败路径", async () => {
  const ran: string[] = [];
  const graph: TaskGraph = {
    nodes: [
      { id: "n1", role: "monitor", run: () => { ran.push("n1"); } },
      { id: "n2", role: "qa", run: () => { throw new Error("fatal"); }, on_fail: "abort" },
      { id: "n3", role: "qa", run: () => { ran.push("n3"); } },
    ],
  };
  const r = await runTaskGraph(graph, { traceId: "tr_tg2" });
  assert.equal(r.ok, false);
  assert.deepEqual(r.executed, ["n1"]);
  assert.deepEqual(ran, ["n1"], "abort 后不得继续执行后续节点");
  assert.equal(r.failed?.node_id, "n2");
  assert.ok((r.failed?.error ?? "").includes("fatal"));
  assert.equal(r.trace_id, "tr_tg2");
});

test("taskgraph：未指定 on_fail 默认 abort（显式失败，不静默）", async () => {
  const r = await runTaskGraph(
    {
      nodes: [
        { id: "n1", role: "qa", run: () => { throw new Error("x"); } },
        { id: "n2", role: "qa", run: () => {} },
      ],
    },
    {},
  );
  assert.equal(r.ok, false);
  assert.deepEqual(r.executed, []);
  assert.equal(r.failed?.node_id, "n1");
});

test("taskgraph：deps 拓扑顺序执行", async () => {
  const ran: string[] = [];
  const r = await runTaskGraph(
    {
      nodes: [
        { id: "c", role: "qa", deps: ["b"], run: () => { ran.push("c"); } },
        { id: "a", role: "monitor", run: () => { ran.push("a"); } },
        { id: "b", role: "enricher", deps: ["a"], run: () => { ran.push("b"); } },
      ],
    },
    {},
  );
  assert.equal(r.ok, true);
  assert.deepEqual(ran, ["a", "b", "c"]);
  assert.deepEqual(r.executed, ["a", "b", "c"]);
});

test("taskgraph：缺依赖 / 循环依赖直接抛错（配置错误不兜底）", async () => {
  await assert.rejects(
    runTaskGraph({ nodes: [{ id: "x", role: "qa", deps: ["missing"], run: () => {} }] }, {}),
    /依赖不存在/,
  );
  await assert.rejects(
    runTaskGraph(
      {
        nodes: [
          { id: "p", role: "qa", deps: ["q"], run: () => {} },
          { id: "q", role: "qa", deps: ["p"], run: () => {} },
        ],
      },
      {},
    ),
    /循环依赖/,
  );
});
