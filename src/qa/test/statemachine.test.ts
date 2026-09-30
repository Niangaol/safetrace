/**
 * A-01 验收：native 后端的拓扑顺序 / abort / degrade / 编译期校验。
 *
 * 历史：曾用同一套断言对 native / langgraph 双后端环跑。langgraph 后端已于 2026-09-30
 * 移除（@langchain/langgraph 从未进 package.json，那 4 个用例永久 skip，是死代码）。
 * 断言内容一条没少，只是不再为不存在的后端空跑一遍。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { compile, loadOrchestrationConfig } from "../src/orchestrator/compile.js";
import type { MachineNode, MachineSpec } from "../src/orchestrator/statemachine.js";

function makeSpec(order: string[], fail: Record<string, string> = {}): MachineSpec {
  const nodes: MachineNode[] = order.map((id) => ({
    id,
    role: "monitor",
    run: () => {
      if (fail[id]) throw new Error(fail[id]);
    },
    on_fail: fail[id] ? "degrade" : undefined,
    deps: id === order[0] ? [] : [order[order.indexOf(id) - 1]!],
  }));
  return { nodes, reducers: {} };
}

const CONFIG = { backend: "native", interrupts: { enabled: false, node_id: null } } as const;

test("[native] 拓扑顺序执行并返回 ok", async () => {
  const executed: string[] = [];
  const spec: MachineSpec = {
    nodes: [
      { id: "a", role: "monitor", run: () => { executed.push("a"); } },
      { id: "b", role: "enricher", deps: ["a"], run: () => { executed.push("b"); } },
      { id: "c", role: "qa", deps: ["b"], run: () => { executed.push("c"); } },
    ],
    reducers: {},
  };
  const { backend: be } = compile(spec, { config: CONFIG });
  const res = await be.run({ traceId: "tr_sm_native", spec });
  assert.equal(res.ok, true, "native should succeed");
  assert.deepEqual(res.executed, ["a", "b", "c"], "native order");
  assert.equal(res.interrupted, false);
  assert.equal(res.failed, null);
  assert.deepEqual(executed, ["a", "b", "c"], "native actually ran nodes");
});

test("[native] abort（默认）停止并交出失败路径", async () => {
  const spec = makeSpec(["a", "b", "c"], { b: "boom" });
  // makeSpec 把失败节点标为 degrade；这里显式改回 abort 语义
  spec.nodes[1]!.on_fail = "abort";
  const { backend: be } = compile(spec, { config: CONFIG });
  const res = await be.run({ traceId: "tr_sm_abort_native", spec });
  assert.equal(res.ok, false, "abort must fail");
  assert.deepEqual(res.executed, ["a"], "stops at failure");
  assert.equal(res.failed?.node_id, "b");
  assert.match(res.failed?.error ?? "", /boom/);
  assert.equal(res.interrupted, false);
});

test("[native] degrade 节点登记后继续", async () => {
  const spec = makeSpec(["a", "b", "c"], { b: "degraded-boom" });
  const { backend: be } = compile(spec, { config: CONFIG });
  const res = await be.run({ traceId: "tr_sm_deg_native", spec });
  assert.equal(res.ok, true, "degrade continues");
  assert.deepEqual(res.executed, ["a", "b", "c"]);
  assert.ok(res.degraded_nodes.some((d) => d.startsWith("b")), "marks degraded");
  assert.equal(res.failed, null);
});

test("[native] 缺依赖 / 成环直接抛错（配置错误不兜底）", () => {
  assert.throws(() => compile({ nodes: [{ id: "x", role: "monitor", run: () => {}, deps: ["ghost"] }] } as MachineSpec, { config: CONFIG }), /依赖不存在/);
  assert.throws(() => compile({ nodes: [
    { id: "p", role: "monitor", run: () => {}, deps: ["q"] },
    { id: "q", role: "enricher", run: () => {}, deps: ["p"] },
  ] } as MachineSpec, { config: CONFIG }), /循环依赖/);
});

test("config/orchestration.yml 默认 native（保 main 可演示）", () => {
  const cfg = loadOrchestrationConfig();
  assert.equal(cfg.backend, "native");
});

test("backend 非法值直接抛错", () => {
  assert.throws(() => compile({ nodes: [] }, { config: { backend: "bogus" as never, interrupts: { enabled: false, node_id: null } } }), /backend 必须是/);
});
