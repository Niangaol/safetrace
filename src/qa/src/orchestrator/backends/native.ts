/** Native sequential executor. State commits/reducers precede durable per-step progress.
 * External side effects are not transactional: callers must use idempotency keys. */
import { nextId } from "@safetrace/shared";
import { isDeepStrictEqual } from "node:util";
import type { BackendContext, MachineBackend, MachineResult, MachineState } from "../statemachine.js";
import { RESUME_VALUE_KEY, topoOrder, businessState } from "../statemachine.js";

export interface NativeRunOptions { interruptAt?: string }

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
    const writable = state as MachineState;
    if (RESUME_VALUE_KEY in state) throw new Error("状态保留键冲突：" + RESUME_VALUE_KEY);
    const finish = (ok: boolean, failed: MachineResult["failed"] = null,
      interruptedAt: string | null = null): MachineResult => ({
      ok, state: businessState(state), executed, degraded_nodes: degraded, failed,
      interrupted: interruptedAt !== null, interrupted_at: interruptedAt, steps, trace_id: traceId,
    });
    for (const node of order) {
      if (alreadyRun.has(node.id)) { executed.push(node.id); continue; }
      if (node.id === this.opts.interruptAt) {
        if (!context.isResume) {
          await context.onInterrupt?.(node.id, context.resumeValue, state);
          return finish(true, null, node.id);
        }
        if (context.resumeValue !== undefined) writable[RESUME_VALUE_KEY] = context.resumeValue;
      }
      const before = structuredClone(state);
      const changed = new Set<string>();
      const assertKey = (key: string | symbol) => {
        if (key === RESUME_VALUE_KEY) throw new Error("状态保留键冲突：" + RESUME_VALUE_KEY);
        if (typeof key === "string") changed.add(key);
      };
      const view = new Proxy(state, {
        set(target, key, value) { assertKey(key); return Reflect.set(target, key, value); },
        defineProperty(target, key, descriptor) { assertKey(key); return Reflect.defineProperty(target, key, descriptor); },
        deleteProperty(target, key) { assertKey(key); return Reflect.deleteProperty(target, key); },
        setPrototypeOf() { throw new Error("禁止修改状态原型"); },
      });
      try {
        await node.run(view);
        for (const field of node.writes ?? []) {
          const reducer = context.spec.reducers?.[field];
          if (reducer && before[field] !== undefined &&
              (changed.has(field) || !isDeepStrictEqual(before[field], writable[field]))) {
            writable[field] = reducer(before[field], writable[field]);
          }
        }
        executed.push(node.id);
        steps.push({ node_id: node.id, status: "ok" });
      } catch (err) {
        // Failed/degraded partial state must not leak to downstream nodes.
        for (const key of Object.keys(writable)) delete writable[key];
        Object.assign(writable, before);
        const error = err instanceof Error ? err.message : String(err);
        if (node.on_fail === "degrade" && !error.includes("保留键冲突")) {
          degraded.push(node.id + "→degraded");
          executed.push(node.id);
          steps.push({ node_id: node.id, status: "degraded", error });
        } else {
          steps.push({ node_id: node.id, status: "failed", error });
          return finish(false, { node_id: node.id, error });
        }
      }
      // Outside node catch: persistence failure is fatal, never treated as degrade.
      await context.onStep?.([...executed], businessState(state) as S);
    }
    return finish(true);
  }
}
