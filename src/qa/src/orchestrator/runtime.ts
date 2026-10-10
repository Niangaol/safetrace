/**
 * A-01 编排运行时：invoke / resume 的真实入口（threadId 持久化 + 挂起恢复）。
 *
 * 口径：
 * - invoke：新线程执行；threadId 缺省由 newThreadId() 生成；挂起点落检查点（suspended）；
 * - resume：按 threadId 取回检查点续跑——跳过已执行节点、恢复状态快照，
 *   并把调用方给出的恢复值注入 state[RESUME_VALUE_KEY]；全部跑完落 completed；
 * - fail-closed：completed 线程禁止重复 invoke；未挂起的线程禁止 resume；
 *   同一 threadId 重复 invoke（已挂起）必须显式走 resume，不静默重跑；
 * - spec 含函数不可序列化：检查点只持久化「进度 + 状态快照」，resume 时调用方提供同一 spec。
 */
import { nextId } from "@safetrace/shared";
import type { MachineSpec, MachineState, ThreadStore } from "./statemachine.js";
import { newThreadId } from "./statemachine.js";
import { compile } from "./compile.js";
import type { OrchestrationConfig } from "./compile.js";

export interface RunMachineOptions<S extends MachineState = MachineState> {
  /** 线程 id；缺省 newThreadId()。给出已存在的 threadId 时按 resume 语义校验。 */
  threadId?: string;
  traceId?: string;
  /** 初始状态（仅新线程有效）。 */
  initialState?: S;
  /** 检查点存储；缺省不持久化（纯内存执行，挂起后无法跨进程 resume）。 */
  store?: ThreadStore;
  /** 编排配置（缺省读 config/orchestration.yml）。 */
  config?: OrchestrationConfig;
}

export interface ResumeMachineOptions<S extends MachineState = MachineState> {
  traceId?: string;
  /** 外部恢复值（resume(threadId, value) 的 value；会注入 state[RESUME_VALUE_KEY]）。 */
  resumeValue?: unknown;
  store?: ThreadStore;
  config?: OrchestrationConfig;
}

export interface MachineRunResult {
  thread_id: string;
  ok: boolean;
  executed: string[];
  degraded_nodes: string[];
  failed: { node_id: string; error: string } | null;
  /** 是否因 interrupt 挂起（等待外部 resume）。 */
  interrupted: boolean;
  interrupted_at: string | null;
  trace_id: string;
}

function nowIso(): string { return new Date().toISOString(); }

/** 新线程执行（invoke）。已存在同 id 检查点 → 显式抛错，禁静默重跑。 */
export async function runMachine<S extends MachineState = MachineState>(
  spec: MachineSpec<S>,
  opts: RunMachineOptions<S> = {},
): Promise<MachineRunResult> {
  const { backend, config } = compile(spec, { config: opts.config });
  const store = opts.store;
  const threadId = opts.threadId ?? newThreadId();
  const traceId = opts.traceId ?? nextId("tr");
  if (store) {
    const prior = await store.loadThreadCheckpoint(threadId);
    if (prior) {
      throw new Error(
        "thread 已存在（status=" + prior.status + "）：重复 invoke 会重跑已执行节点，请改用 resumeMachine（" + threadId + "）",
      );
    }
  }
  const suspension: { current: { node_id: string; state: S } | null } = { current: null };
  const result = await backend.run({
    traceId,
    spec,
    ...(opts.initialState ? { initialState: opts.initialState } : {}),
    onInterrupt: async (nodeId, _value, state) => {
      suspension.current = { node_id: nodeId, state: structuredClone(state) };
    },
  });
  if (store) {
    if (suspension.current) {
      await store.saveThreadCheckpoint({
        thread_id: threadId,
        trace_id: traceId,
        executed: [...result.executed],
        interrupt_node_id: suspension.current.node_id,
        state: suspension.current.state as Record<string, unknown>,
        status: "suspended",
        updated_at: nowIso(),
      });
    } else if (result.ok) {
      await store.saveThreadCheckpoint({
        thread_id: threadId,
        trace_id: traceId,
        executed: [...result.executed],
        interrupt_node_id: result.executed.at(-1) ?? "",
        state: {},
        status: "completed",
        updated_at: nowIso(),
      });
    }
    // result.ok=false（abort）不落检查点：失败路径无状态可恢复，重试即全新执行。
  }
  return {
    thread_id: threadId,
    ok: result.ok,
    executed: result.executed,
    degraded_nodes: result.degraded_nodes,
    failed: result.failed,
    interrupted: result.interrupted,
    interrupted_at: result.interrupted_at,
    trace_id: result.trace_id,
  };
}

/** 按 threadId 恢复挂起的线程（resume）。未挂起 / 不存在 → 显式抛错。 */
export async function resumeMachine<S extends MachineState = MachineState>(
  threadId: string,
  spec: MachineSpec<S>,
  opts: ResumeMachineOptions<S> = {},
): Promise<MachineRunResult> {
  const store = opts.store;
  if (!store) throw new Error("resume 必须提供 thread store（检查点是恢复的唯一依据）");
  const prior = await store.loadThreadCheckpoint(threadId);
  if (!prior) throw new Error("thread 不存在：" + threadId);
  if (prior.status !== "suspended") throw new Error("thread 非挂起态（status=" + prior.status + "），不能 resume：" + threadId);
  const { backend, config } = compile(spec, { config: opts.config });
  const traceId = opts.traceId ?? prior.trace_id;
  const suspension: { current: { node_id: string; state: S } | null } = { current: null };
  const result = await backend.run({
    traceId,
    spec,
    initialState: prior.state as S,
    executed: [...prior.executed],
    isResume: true,
    ...(opts.resumeValue !== undefined ? { resumeValue: opts.resumeValue } : {}),
    onInterrupt: async (nodeId, _value, state) => {
      suspension.current = { node_id: nodeId, state: structuredClone(state) };
    },
  });
  // resume 后可能再次挂起（多层交互）：覆盖检查点保持 suspended；否则 completed。
  if (result.interrupted && result.interrupted_at && suspension.current) {
    await store.saveThreadCheckpoint({
      thread_id: threadId,
      trace_id: traceId,
      executed: [...result.executed],
      interrupt_node_id: suspension.current.node_id,
      state: suspension.current.state as Record<string, unknown>,
      status: "suspended",
      updated_at: nowIso(),
    });
  } else if (result.ok) {
    await store.saveThreadCheckpoint({
      thread_id: threadId,
      trace_id: traceId,
      executed: [...result.executed],
      interrupt_node_id: result.executed.at(-1) ?? "",
      state: {},
      status: "completed",
      updated_at: nowIso(),
    });
  }
  return {
    thread_id: threadId,
    ok: result.ok,
    executed: result.executed,
    degraded_nodes: result.degraded_nodes,
    failed: result.failed,
    interrupted: result.interrupted,
    interrupted_at: result.interrupted_at,
    trace_id: result.trace_id,
  };
}