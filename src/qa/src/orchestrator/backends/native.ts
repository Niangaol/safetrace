/**
 * A-01 native 后端：自研顺序执行器（迁移自 taskgraph.ts 的拓扑+失败策略语义）。
 * 作为默认后端保 main 可演示；不引入外部依赖。
 * A-01（2026-10-10）补齐挂起/恢复的状态流：
 * - 节点间共享同一个 state（初始状态 / resume 快照可注入）；
 * - 节点声明 writes 的字段在重复写入时按 spec.reducers 合并（缺省 last-write-wins）；
 * - interrupt 命中且非 resume → 挂起并交出挂起点状态；resume → 跳过已执行节点，
 *   把外部恢复值注入 state[RESUME_VALUE_KEY] 后继续执行挂起节点。
 */
import { nextId } from "@safetrace/shared";
import type { BackendContext, MachineBackend, MachineNode, MachineResult, MachineState } from "../statemachine.js";
import { RESUME_VALUE_KEY, topoOrder } from "../statemachine.js";

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
    const alreadyRun = new Set(context.executed ?? []);
    const state = (context.initialState ?? {}) as S;
    // 同一对象的非泛型可变视图：泛型 S 的索引只读，写入经此视图（节点拿到的仍是 S）。
    const writable = state as MachineState;
    if (context.isResume && context.resumeValue !== undefined && RESUME_VALUE_KEY in state) {
      throw new Error("恢复值与状态保留键冲突：" + RESUME_VALUE_KEY);
    }

    for (const node of order) {
      // resume：跳过检查点里已执行的节点（不重跑，副作用不重复）。
      if (alreadyRun.has(node.id)) {
        executed.push(node.id);
        continue;
      }
      // interrupt：命中挂起点。
      if (this.opts.interruptAt && node.id === this.opts.interruptAt) {
        if (context.isResume) {
          // resume 续跑：恢复值注入保留键后执行该节点（挂起点本身尚未执行过）。
          if (context.resumeValue !== undefined) writable[RESUME_VALUE_KEY] = context.resumeValue;
        } else {
          await context.onInterrupt?.(node.id, context.resumeValue, state);
          return { ok: true, executed, degraded_nodes: degraded, failed: null, interrupted: true, interrupted_at: node.id, steps, trace_id: traceId };
        }
      }
      const writes = node.writes ?? [];
      const before = new Map<string, unknown>(writes.map((field) => [field, state[field]]));
      try {
        await node.run(state);
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
        return { ok: false, executed, degraded_nodes: degraded, failed: { node_id: node.id, error }, interrupted: false, interrupted_at: null, steps, trace_id: traceId };
      }
      // reducers：节点重复写入同名字段时按声明的合并策略收敛（缺省 last-write-wins）。
      for (const field of writes) {
        const reducer = context.spec.reducers?.[field];
        const previous = before.get(field);
        if (reducer && previous !== undefined && writable[field] !== previous) {
          writable[field] = reducer(previous, writable[field]);
        }
      }
    }
    return { ok: true, executed, degraded_nodes: degraded, failed: null, interrupted: false, interrupted_at: null, steps, trace_id: traceId };
  }
}