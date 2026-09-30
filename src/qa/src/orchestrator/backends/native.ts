/**
 * A-01 native 后端：自研顺序执行器（迁移自 taskgraph.ts 的拓扑+失败策略语义）。
 * 作为默认后端保 main 可演示；不引入外部依赖。
 */
import { nextId } from "@safetrace/shared";
import type { BackendContext, MachineBackend, MachineNode, MachineResult, MachineState } from "../statemachine.js";
import { topoOrder } from "../statemachine.js";

export interface NativeRunOptions {
  /** interrupt 节点 id：执行到该节点时挂起（等待 resume）。 */
  interruptAt?: string;
}

export class NativeMachineBackend<S extends MachineState = MachineState> implements MachineBackend<S> {
  readonly name = "native" as const;

  constructor(private readonly opts: NativeRunOptions = {}) {}

  async run(context: BackendContext<S>): Promise<MachineResult> {
    const traceId = context.traceId ?? nextId("tr");
    const order = topoOrder(context.spec.nodes);
    const executed: string[] = [];
    const degraded: string[] = [];
    const steps: MachineResult["steps"] = [];

    for (const node of order) {
      // interrupt：命中挂起点则停下，交出 interrupted=true（不视为失败）。
      if (this.opts.interruptAt && node.id === this.opts.interruptAt) {
        await context.onInterrupt?.(node.id, context.resumeValue);
        return { ok: true, executed, degraded_nodes: degraded, failed: null, interrupted: true, steps, trace_id: traceId };
      }
      try {
        await node.run({} as S);
        executed.push(node.id);
        steps.push({ node_id: node.id, status: "ok" });
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        if (node.on_fail === "degrade") {
          // 降级语义由上层（taskgraph/runtime）登记 FallbackEvent；后端只标记状态。
          degraded.push(node.id + "→degraded");
          executed.push(node.id);
          steps.push({ node_id: node.id, status: "degraded", error });
          continue;
        }
        // abort（默认）：停止并交出失败路径，不产生降级答案。
        steps.push({ node_id: node.id, status: "failed", error });
        return { ok: false, executed, degraded_nodes: degraded, failed: { node_id: node.id, error }, interrupted: false, steps, trace_id: traceId };
      }
    }
    return { ok: true, executed, degraded_nodes: degraded, failed: null, interrupted: false, steps, trace_id: traceId };
  }
}
