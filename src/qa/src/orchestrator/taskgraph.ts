/**
 * 编排层 TaskGraph：节点按依赖拓扑顺序执行（顺序执行，便于追踪与回放）。
 * 失败语义（红线：禁止静默兜底）：
 * - on_fail="degrade"：经 shared.degrade() 登记 FallbackEvent 并 emit 到总线，节点以 degraded 标记继续；
 * - on_fail="abort"（默认）：立即停止，返回失败路径（executed/failed），不产生任何降级答案。
 */
import { degrade, nextId } from "@safetrace/shared";
import type { EventBus, FallbackEvent } from "@safetrace/shared";
import type { AgentRoleName } from "./roles.js";
import type { MachineState } from "./statemachine.js";

export interface TaskNode {
  id: string;
  role: AgentRoleName;
  /** A-01：可选接收编排状态（旧节点忽略该参数即可，签名兼容）。 */
  run: (state?: MachineState) => void | Promise<void>;
  /** 失败策略，缺省 = "abort"（显式失败，不静默） */
  on_fail?: "degrade" | "abort";
  /** 依赖节点 id；拓扑排序用（声明顺序作为同层顺序） */
  deps?: string[];
}

export interface TaskGraph {
  nodes: TaskNode[];
}

export interface TaskFailure {
  node_id: string;
  error: string;
}

export interface TaskGraphResult {
  ok: boolean;
  /** 实际执行过的节点 id（含 degrade 继续的节点） */
  executed: string[];
  /** 降级继续的节点标记：nodeId→degraded_to */
  degraded_nodes: string[];
  /** abort 停止时的失败节点；ok=true 时为 null */
  failed: TaskFailure | null;
  trace_id: string;
}

/** A-01：经状态机适配层执行的结果（额外带线程与挂起信息）。 */
export interface TaskGraphMachineResult extends TaskGraphResult {
  /** 编排线程 id（挂起后据此 resume）。 */
  thread_id: string;
  /** 是否因 interrupt 挂起（等待外部 resume）。 */
  interrupted: boolean;
  /** 挂起点节点 id；未挂起为 null。 */
  interrupted_at: string | null;
}

export interface RunTaskGraphOptions {
  bus?: EventBus;
  traceId?: string;
}

/** Kahn 拓扑排序：同层保持声明顺序；缺依赖 / 成环直接抛错（配置错误不兜底）。 */
function topoOrder(nodes: TaskNode[]): TaskNode[] {
  const byId = new Map(nodes.map((n) => [n.id, n] as const));
  for (const n of nodes) {
    for (const d of n.deps ?? []) {
      if (!byId.has(d)) throw new Error("任务图依赖不存在：" + n.id + " → " + d);
    }
  }
  const done = new Set<string>();
  const remaining = [...nodes];
  const order: TaskNode[] = [];
  while (remaining.length > 0) {
    const idx = remaining.findIndex((n) => (n.deps ?? []).every((d) => done.has(d)));
    if (idx === -1) throw new Error("任务图存在循环依赖（或依赖无法满足）");
    const node = remaining.splice(idx, 1)[0];
    if (!node) throw new Error("任务图拓扑排序内部错误");
    done.add(node.id);
    order.push(node);
  }
  return order;
}

async function emitFallback(bus: EventBus | undefined, event: FallbackEvent): Promise<void> {
  if (!bus) return;
  await bus.publish("fallback.events", event, { trace_id: event.trace_id });
}

/** 顺序执行任务图。节点失败是被管理的语义，不向上抛异常。 */
export async function runTaskGraph(graph: TaskGraph, opts: RunTaskGraphOptions = {}): Promise<TaskGraphResult> {
  const traceId = opts.traceId ?? nextId("tr");
  const order = topoOrder(graph.nodes);
  const executed: string[] = [];
  const degraded: string[] = [];

  for (const node of order) {
    try {
      await node.run();
      executed.push(node.id);
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      if (node.on_fail === "degrade") {
        const res = await degrade({
          layer: "L1",
          trigger: "任务 " + node.id + "（" + node.role + "）执行失败: " + error,
          degradedOf: "task:" + node.id,
          traceId,
          label: "任务 " + node.id + " 失败，已按降级策略继续，结果可能不完整",
          recoveryHint: "修复该任务后重放对应 trace 即可恢复",
          emit: (e) => emitFallback(opts.bus, e),
        });
        degraded.push(node.id + "→" + res.degraded_to);
        executed.push(node.id);
        continue;
      }
      // abort（默认）：停止并交出失败路径
      return { ok: false, executed, degraded_nodes: degraded, failed: { node_id: node.id, error }, trace_id: traceId };
    }
  }
  return { ok: true, executed, degraded_nodes: degraded, failed: null, trace_id: traceId };
}
