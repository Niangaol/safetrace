/**
 * A-01 StateMachine 适配层：编排执行统一走 MachineBackend 抽象。
 * 纪律：
 * - 业务侧只依赖本文件的接口与 compile()，不直接 import 具体后端；
 * - 后端固定为 native（自研顺序执行器，零外部依赖）；langgraph 后端已于 2026-09-30 移除；
 * - 迁移期 taskgraph.ts 保持原语义不动，由 compile() 把旧图编译成状态机描述。
 */
import { nextId } from "@safetrace/shared";

export type MachineFailurePolicy = "abort" | "degrade";

/** 跨节点共享状态：reducers 决定同名字段如何合并。 */
export interface MachineState {
  readonly [key: string]: unknown;
}

export type MachineReducer = (current: unknown, incoming: unknown) => unknown;
export type MachineReducers = Record<string, MachineReducer>;

export interface MachineNode<S extends MachineState = MachineState> {
  id: string;
  /** 角色名（编排层审计用，取值见 orchestrator/roles.ts）。 */
  role: string;
  run: (state: S) => void | Promise<void>;
  /** 失败策略，缺省 "abort"（显式失败，不静默）。 */
  on_fail?: MachineFailurePolicy;
  /** 依赖节点 id。 */
  deps?: string[];
  /** 声明本节点会写入的状态字段（用于冲突检测与审计）。 */
  writes?: string[];
}

export interface MachineSpec<S extends MachineState = MachineState> {
  nodes: MachineNode<S>[];
  reducers?: MachineReducers;
}

export interface MachineStepRecord {
  node_id: string;
  status: "ok" | "degraded" | "failed";
  error?: string;
}

export interface MachineResult {
  ok: boolean;
  /** 实际执行过的节点 id（含 degrade 继续的节点）。 */
  executed: string[];
  /** 降级继续的节点标记：nodeId→degraded_to。 */
  degraded_nodes: string[];
  /** abort 停止时的失败节点；ok=true 时为 null。 */
  failed: { node_id: string; error: string } | null;
  /** 是否因 interrupt 挂起（等待外部 resume）。 */
  interrupted: boolean;
  /** 每个节点的执行明细（顺序同 executed）。 */
  steps: MachineStepRecord[];
  trace_id: string;
}

export interface BackendContext<S extends MachineState = MachineState> {
  traceId: string;
  spec: MachineSpec<S>;
  /** interrupt 挂起回调：命中时置 interrupted=true 并停下。 */
  onInterrupt?: (nodeId: string, value: unknown) => void | Promise<void>;
  /** 外部恢复值（resume(threadId, value) 写入）。 */
  resumeValue?: unknown;
}

/** 后端接口（当前仅 native 一个实现）。 */
export interface MachineBackend<S extends MachineState = MachineState> {
  readonly name: "native";
  run(context: BackendContext<S>): Promise<MachineResult>;
}

/*** 默认 reducers：last-write-wins 之外提供常用合并策略。 */
export const defaultReducers: MachineReducers = {
  // 数组累加（同名字段多次写入时拼接去重）
  collect: (current, incoming) => {
    const left = Array.isArray(current) ? current : [];
    const right = Array.isArray(incoming) ? incoming : [incoming];
    return [...left, ...right];
  },
  // 计数累加
  count: (current, incoming) => (typeof current === "number" ? current : 0) + (typeof incoming === "number" ? incoming : 1),
};

/** 校验 spec：缺依赖 / 成环直接抛错（配置错误不兜底）。 */
export function validateSpec<S extends MachineState>(nodes: MachineNode<S>[]): void {
  const byId = new Map(nodes.map((n) => [n.id, n] as const));
  for (const n of nodes) {
    for (const d of n.deps ?? []) {
      if (!byId.has(d)) throw new Error("状态机依赖不存在：" + n.id + " → " + d);
    }
  }
  const done = new Set<string>();
  const remaining = [...nodes];
  while (remaining.length > 0) {
    const idx = remaining.findIndex((n) => (n.deps ?? []).every((d) => done.has(d)));
    if (idx === -1) throw new Error("状态机存在循环依赖（或依赖无法满足）");
    const node = remaining.splice(idx, 1)[0];
    if (!node) throw new Error("状态机拓扑排序内部错误");
    done.add(node.id);
  }
}

/** 拓扑排序：同层保持声明顺序。 */
export function topoOrder<S extends MachineState>(nodes: MachineNode<S>[]): MachineNode<S>[] {
  validateSpec(nodes);
  const done = new Set<string>();
  const remaining = [...nodes];
  const order: MachineNode<S>[] = [];
  while (remaining.length > 0) {
    const idx = remaining.findIndex((n) => (n.deps ?? []).every((d) => done.has(d)));
    const node = idx === -1 ? undefined : remaining.splice(idx, 1)[0];
    if (!node) throw new Error("状态机拓扑排序内部错误");
    done.add(node.id);
    order.push(node);
  }
  return order;
}

/** 生成 threadId（resume 的挂载点）。 */
export function newThreadId(): string {
  return nextId("thread");
}
