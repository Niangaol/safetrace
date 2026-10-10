/** Durable invoke/resume. A lease is never expired automatically.
 * Snapshot/transport failure after execution starts retains the lease and requires
 * manual audit. External side effects still require caller-owned idempotency. */
import { randomUUID } from "node:crypto";
import { nextId } from "@safetrace/shared";
import type { ThreadCheckpoint } from "@safetrace/shared";
import type { MachineSpec, MachineState, MachineResult, ThreadStore } from "./statemachine.js";
import { newThreadId, RESUME_VALUE_KEY, specFingerprint, topoOrder, businessState } from "./statemachine.js";
import { compile } from "./compile.js";
import type { OrchestrationConfig } from "./compile.js";

export interface RunMachineOptions<S extends MachineState = MachineState> {
  threadId?: string;
  traceId?: string;
  initialState?: S;
  store?: ThreadStore;
  config?: OrchestrationConfig;
}
export interface ResumeMachineOptions<S extends MachineState = MachineState> {
  traceId?: string;
  resumeValue?: unknown;
  store?: ThreadStore;
  config?: OrchestrationConfig;
}
export interface MachineRunResult extends MachineResult { thread_id: string }

export async function runMachine<S extends MachineState = MachineState>(
  spec: MachineSpec<S>, opts: RunMachineOptions<S> = {},
): Promise<MachineRunResult> {
  return execute(spec, opts, false);
}

/** Retry failed threads explicitly; completed/running threads cannot be resumed. */
export async function resumeMachine<S extends MachineState = MachineState>(
  threadId: string, spec: MachineSpec<S>, opts: ResumeMachineOptions<S> = {},
): Promise<MachineRunResult> {
  if (!opts.store) throw new Error("resume 必须提供 thread store（检查点是恢复的唯一依据）");
  return execute(spec, { ...opts, threadId }, true, opts.resumeValue);
}

async function execute<S extends MachineState>(
  spec: MachineSpec<S>, opts: RunMachineOptions<S>, resume: boolean, resumeValue?: unknown,
): Promise<MachineRunResult> {
  let compiled = compile(spec, { config: opts.config });
  const threadId = opts.threadId ?? newThreadId();
  const store = opts.store;
  const token = randomUUID();
  const fingerprint = specFingerprint(spec);
  const order = topoOrder(spec.nodes);
  if (!resume && compiled.config.interrupts.enabled &&
      (!compiled.config.interrupts.node_id || !order.some(n => n.id === compiled.config.interrupts.node_id))) {
    throw new Error("interrupt 节点不存在，禁止静默绕过挂起");
  }
  if (!resume && opts.initialState && RESUME_VALUE_KEY in opts.initialState) {
    throw new Error("状态保留键冲突：" + RESUME_VALUE_KEY);
  }
  if (store && !await store.acquireThreadLease(threadId, token)) {
    throw new Error("thread 租约占用，禁止并发执行；需人工审计解锁：" + threadId);
  }
  let started = false;
  try {
    const prior = store ? await store.loadThreadCheckpoint(threadId) : undefined;
    if (!resume && prior) {
      throw new Error("thread 已存在（status=" + prior.status + "），请显式 resume：" + threadId);
    }
    if (resume) {
      if (!prior) throw new Error("thread 不存在：" + threadId);
      if (prior.status !== "suspended" && prior.status !== "failed") {
        throw new Error("thread 非挂起态/可重试失败态（status=" + prior.status + "），不能 resume：" + threadId);
      }
      if (!prior.spec_fingerprint || prior.spec_fingerprint !== fingerprint) {
        throw new Error("thread spec_fingerprint 不匹配（旧检查点需人工迁移）：" + threadId);
      }
      if (prior.executed.some((id, i) => order[i]?.id !== id) ||
          order[prior.executed.length]?.id !== prior.interrupt_node_id) {
        throw new Error("thread 检查点进度/挂起节点与图不匹配：" + threadId);
      }
      if (RESUME_VALUE_KEY in prior.state) throw new Error("状态保留键冲突：" + RESUME_VALUE_KEY);
      // The checkpoint, not today's config, defines where the value belongs.
      compiled = compile(spec, { config: { backend: "native", interrupts: {
        enabled: true, node_id: prior.interrupt_node_id,
      } } });
    }
    const traceId = opts.traceId ?? prior?.trace_id ?? nextId("tr");
    const initialState = (prior?.state ?? opts.initialState ?? {}) as S;
    businessState(initialState); // validate before any node side effects
    const save = async (status: ThreadCheckpoint["status"], executed: string[],
      state: MachineState, target: string) => {
      if (store) await store.saveThreadCheckpoint({
        thread_id: threadId, trace_id: traceId, executed: [...executed],
        state: businessState(state), interrupt_node_id: target, status,
        spec_fingerprint: fingerprint, updated_at: new Date().toISOString(),
      });
    };
    // From here on, any unexpected failure keeps the durable claim (fail closed).
    started = true;
    await save("running", prior?.executed ?? [], initialState,
      prior?.interrupt_node_id ?? order[0]?.id ?? "");
    const result = await compiled.backend.run({
      traceId, spec, initialState, executed: prior?.executed ?? [],
      isResume: resume, resumeValue,
      onStep: async (executed, state) => {
        await save("running", executed, state, order[executed.length]?.id ?? "");
      },
    });
    await save(result.interrupted ? "suspended" : result.ok ? "completed" : "failed",
      result.executed, result.state,
      result.interrupted_at ?? result.failed?.node_id ?? result.executed.at(-1) ?? "");
    if (store && !await store.releaseThreadLease(threadId, token)) {
      throw new Error("thread 租约所有权丢失，需人工审计：" + threadId);
    }
    return { ...result, thread_id: threadId };
  } catch (error) {
    // Validation happens before execution and may safely relinquish ownership.
    if (store && !started) await store.releaseThreadLease(threadId, token);
    throw error;
  }
}
