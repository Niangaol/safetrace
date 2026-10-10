/**
 * A-01 适配层桥接：把旧 TaskGraph 编译成 MachineSpec 走统一后端。
 * 目的：迁移期两条路径语义一致；taskgraph.ts 原实现保留不动直至 A-01/A-02 收口。
 * A-01（2026-10-10）：接通挂起/恢复——threadId 贯穿、检查点落库、resume 续跑。
 */
import type { TaskGraph, RunTaskGraphOptions } from "./taskgraph.js";
import type { TaskGraphMachineResult } from "./taskgraph.js";
import { compile } from "./compile.js";
import type { MachineNode, MachineSpec, MachineState, ThreadStore } from "./statemachine.js";
import { newThreadId } from "./statemachine.js";
import { degrade, EventBus } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";

/** TaskNode → MachineNode（保留 id/role/deps/on_fail/run 语义；state 透传给节点）。 */
export function taskGraphToSpec(graph: TaskGraph): MachineSpec {
  const nodes: MachineNode[] = graph.nodes.map((n) => ({
    id: n.id,
    role: n.role,
    run: (state?: MachineState) => n.run(state),
    ...(n.on_fail ? { on_fail: n.on_fail } : {}),
    ...(n.deps ? { deps: n.deps } : {}),
  }));
  return { nodes, reducers: {} };
}

async function emitFallback(bus: EventBus | undefined, event: FallbackEvent): Promise<void> {
  if (!bus) return;
  await bus.publish("fallback.events", event, { trace_id: event.trace_id });
}

export interface RunTaskGraphViaMachineOptions extends RunTaskGraphOptions {
  /** 线程 id；缺省新生成。给出已挂起的 threadId 时按 resume 语义校验（禁静默重跑）。 */
  threadId?: string;
  /** 检查点存储；提供才具备跨进程挂起/恢复能力。 */
  threadStore?: ThreadStore;
  /** resume 用的外部恢复值（注入 state[RESUME_VALUE_KEY]）。 */
  resumeValue?: unknown;
}

/**
 * 经适配层执行 TaskGraph。失败语义与 runTaskGraph 一致：
 * - degrade：登记 FallbackEvent 并继续；
 * - abort（默认）：停止并返回失败路径；
 * - interrupt（config/interchestration.yml 启用时）：挂起并落检查点，返回 interrupted=true。
 */
export async function runTaskGraphViaMachine(graph: TaskGraph, opts: RunTaskGraphViaMachineOptions = {}): Promise<TaskGraphMachineResult> {
  const traceId = opts.traceId;
  const spec = taskGraphToSpec(graph);
  const { backend, config } = compile(spec);
  // threadId 缺省自动生成（与 runMachine 同口径：线程身份始终存在，挂起后才能据它 resume）
  const threadId = opts.threadId ?? newThreadId();
  const store = opts.threadStore;
  const suspension: { current: { node_id: string; state: MachineState } | null } = { current: null };
  const isResume = store !== undefined && opts.resumeValue !== undefined;
  let initialState: MachineState | undefined;
  let executedBefore: string[] | undefined;
  if (store) {
    const prior = await store.loadThreadCheckpoint(threadId);
    if (prior) {
      if (prior.status !== "suspended") {
        throw new Error("thread 非挂起态（status=" + prior.status + "），不能续跑：" + threadId);
      }
      if (opts.resumeValue === undefined) {
        throw new Error("thread 已挂起，续跑必须提供 resumeValue：" + threadId);
      }
      initialState = prior.state;
      executedBefore = [...prior.executed];
    }
  }
  const result = await backend.run({
    traceId: traceId ?? "",
    spec,
    ...(initialState ? { initialState } : {}),
    ...(executedBefore ? { executed: executedBefore } : {}),
    ...(isResume ? { isResume: true } : {}),
    ...(isResume && opts.resumeValue !== undefined ? { resumeValue: opts.resumeValue } : {}),
    onInterrupt: async (nodeId, _value, state) => {
      suspension.current = { node_id: nodeId, state: structuredClone(state) };
    },
  });
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
  if (store) {
    if (result.interrupted && suspension.current) {
      await store.saveThreadCheckpoint({
        thread_id: threadId,
        trace_id: result.trace_id,
        executed: [...result.executed],
        interrupt_node_id: suspension.current.node_id,
        state: suspension.current.state as Record<string, unknown>,
        status: "suspended",
        updated_at: new Date().toISOString(),
      });
    } else if (result.ok) {
      await store.saveThreadCheckpoint({
        thread_id: threadId,
        trace_id: result.trace_id,
        executed: [...result.executed],
        interrupt_node_id: result.executed.at(-1) ?? "",
        state: {},
        status: "completed",
        updated_at: new Date().toISOString(),
      });
    }
  }
  return {
    ok: result.ok,
    executed: result.executed,
    degraded_nodes: degraded.length > 0 ? degraded : result.degraded_nodes,
    failed: result.failed,
    trace_id: result.trace_id,
    backend: config.backend,
    thread_id: threadId,
    interrupted: result.interrupted,
    interrupted_at: result.interrupted_at,
  } as TaskGraphMachineResult;
}