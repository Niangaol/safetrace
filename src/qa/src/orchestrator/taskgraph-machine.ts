/**
 * A-01 适配层桥接：把旧 TaskGraph 编译成 MachineSpec 走统一后端。
 * 目的：迁移期两条路径语义一致；taskgraph.ts 原实现保留不动直至 A-01/A-02 收口。
 */
import type { TaskGraph, TaskGraphResult, RunTaskGraphOptions } from "./taskgraph.js";
import { compile } from "./compile.js";
import type { MachineNode, MachineSpec } from "./statemachine.js";
import { degrade, EventBus } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";

/** TaskNode → MachineNode（保留 id/role/deps/on_fail/run 语义）。 */
export function taskGraphToSpec(graph: TaskGraph): MachineSpec {
  const nodes: MachineNode[] = graph.nodes.map((n) => ({
    id: n.id,
    role: n.role,
    run: n.run,
    ...(n.on_fail ? { on_fail: n.on_fail } : {}),
    ...(n.deps ? { deps: n.deps } : {}),
  }));
  return { nodes, reducers: {} };
}

async function emitFallback(bus: EventBus | undefined, event: FallbackEvent): Promise<void> {
  if (!bus) return;
  await bus.publish("fallback.events", event, { trace_id: event.trace_id });
}

/**
 * 经适配层执行 TaskGraph。失败语义与 runTaskGraph 一致：
 * - degrade：登记 FallbackEvent 并继续；
 * - abort（默认）：停止并返回失败路径。
 */
export async function runTaskGraphViaMachine(graph: TaskGraph, opts: RunTaskGraphOptions = {}): Promise<TaskGraphResult> {
  const traceId = opts.traceId;
  const spec = taskGraphToSpec(graph);
  const { backend, config } = compile(spec);
  const result = await backend.run({ traceId: traceId ?? "", spec, resumeValue: undefined });
  const degraded: string[] = [];
  // 后端只标记 degraded 状态；FallbackEvent 登记在此完成（与 taskgraph.ts 同口径）。
  for (const step of result.steps) {
    if (step.status !== "degraded") continue;
    const node = graph.nodes.find((n) => n.id === step.node_id);
    const res = await degrade({
      layer: "L1",
      trigger: "任务 " + step.node_id + "（" + (node?.role ?? "unknown") + "）执行失败: " + (step.error ?? ""),
      degradedOf: "task:" + step.node_id,
      traceId: result.trace_id,
      label: "任务 " + step.node_id + " 失败，已按降级策略继续，结果可能不完整",
      recoveryHint: "修复该任务后重放对应 trace 即可恢复",
      emit: (e) => emitFallback(opts.bus, e),
    });
    degraded.push(step.node_id + "→" + res.degraded_to);
  }
  return {
    ok: result.ok,
    executed: result.executed,
    degraded_nodes: degraded.length > 0 ? degraded : result.degraded_nodes,
    failed: result.failed,
    trace_id: result.trace_id,
    backend: config.backend,
  } as TaskGraphResult;
}
