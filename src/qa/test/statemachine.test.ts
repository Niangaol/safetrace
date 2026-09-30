/**
 * A-01 验收：同一套断言对 native / langgraph 两个后端环跑。
 * langgraph 未安装时该用例必须显式失败（禁静默降级到 native）。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { compile, loadOrchestrationConfig } from "../src/orchestrator/compile.js";
import { createRequire } from "node:module";

/** langgraph 依赖是否可用（未安装时相关用例显式跳过，不假装通过）。 */
const langgraphAvailable = (() => {
  try {
    const req = createRequire(import.meta.url);
    const mod = req("@langchain/langgraph") as { StateGraph?: unknown };
    return typeof mod.StateGraph === "function";
  } catch {
    return false;
  }
})();
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

const BACKENDS = ["native", "langgraph"] as const;

for (const backend of BACKENDS) {
  const it = backend === "langgraph" && !langgraphAvailable ? test.skip : test;
  it(`[${backend}] 拓扑顺序执行并返回 ok`, async () => {
    const executed: string[] = [];
    const spec: MachineSpec = {
      nodes: [
        { id: "a", role: "monitor", run: () => { executed.push("a"); } },
        { id: "b", role: "enricher", deps: ["a"], run: () => { executed.push("b"); } },
        { id: "c", role: "qa", deps: ["b"], run: () => { executed.push("c"); } },
      ],
      reducers: {},
    };
    const { backend: be } = compile(spec, { config: { backend, interrupts: { enabled: false, node_id: null } }, langgraphLoader: () => undefined });
    const res = await be.run({ traceId: "tr_sm_" + backend, spec });
    assert.equal(res.ok, true, backend + " should succeed");
    assert.deepEqual(res.executed, ["a", "b", "c"], backend + " order");
    assert.equal(res.interrupted, false);
    assert.equal(res.failed, null);
    assert.deepEqual(executed, ["a", "b", "c"], backend + " actually ran nodes");
  });

  it(`[${backend}] abort（默认）停止并交出失败路径`, async () => {
    const spec = makeSpec(["a", "b", "c"], { b: "boom" });
    // makeSpec 把失败节点标为 degrade；这里显式改回 abort 语义
    spec.nodes[1]!.on_fail = "abort";
    const { backend: be } = compile(spec, { config: { backend, interrupts: { enabled: false, node_id: null } }, langgraphLoader: () => undefined });
    const res = await be.run({ traceId: "tr_sm_abort_" + backend, spec });
    assert.equal(res.ok, false, backend + " abort must fail");
    assert.deepEqual(res.executed, ["a"], backend + " stops at failure");
    assert.equal(res.failed?.node_id, "b");
    assert.match(res.failed?.error ?? "", /boom/);
    assert.equal(res.interrupted, false);
  });

  it(`[${backend}] degrade 节点登记后继续`, async () => {
    const spec = makeSpec(["a", "b", "c"], { b: "degraded-boom" });
    const { backend: be } = compile(spec, { config: { backend, interrupts: { enabled: false, node_id: null } }, langgraphLoader: () => undefined });
    const res = await be.run({ traceId: "tr_sm_deg_" + backend, spec });
    assert.equal(res.ok, true, backend + " degrade continues");
    assert.deepEqual(res.executed, ["a", "b", "c"]);
    assert.ok(res.degraded_nodes.some((d) => d.startsWith("b")), backend + " marks degraded");
    assert.equal(res.failed, null);
  });

  it(`[${backend}] 缺依赖 / 成环直接抛错（配置错误不兜底）`, () => {
    assert.throws(() => compile({ nodes: [{ id: "x", role: "monitor", run: () => {}, deps: ["ghost"] }] } as MachineSpec, { config: { backend, interrupts: { enabled: false, node_id: null } } }), /依赖不存在/);
    assert.throws(() => compile({ nodes: [
      { id: "p", role: "monitor", run: () => {}, deps: ["q"] },
      { id: "q", role: "enricher", run: () => {}, deps: ["p"] },
    ] } as MachineSpec, { config: { backend, interrupts: { enabled: false, node_id: null } } }), /循环依赖/);
  });
}

test("config/orchestration.yml 默认 native（保 main 可演示）", () => {
  const cfg = loadOrchestrationConfig();
  assert.equal(cfg.backend, "native");
});

test("backend 非法值直接抛错", () => {
  assert.throws(() => compile({ nodes: [] }, { config: { backend: "bogus" as never, interrupts: { enabled: false, node_id: null } } }), /backend 必须是/);
});

test("langgraph 依赖缺失时显式失败，不静默降级", async () => {
  const spec: MachineSpec = { nodes: [{ id: "a", role: "monitor", run: () => {} }], reducers: {} };
  const { backend: be } = compile(spec, {
    config: { backend: "langgraph", interrupts: { enabled: false, node_id: null } },
    langgraphLoader: () => { throw new Error("boom: @langchain/langgraph not installed"); },
  });
  await assert.rejects(be.run({ traceId: "tr_sm_lg_missing", spec }), /not installed/);
});
