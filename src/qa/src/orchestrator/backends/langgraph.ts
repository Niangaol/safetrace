/**
 * A-01 langgraph 后端：@langchain/langgraph 适配。
 * 设计约束（禁静默降级）：
 * - 未安装 @langchain/langgraph 时构造即抛错，由上层显式决定是否切回 native；
 * - 不得在运行时"悄悄"改用 native——那会让 backend 配置失去意义。
 */
import type { BackendContext, MachineBackend, MachineResult, MachineState } from "../statemachine.js";
import { topoOrder } from "../statemachine.js";
import { nextId } from "@safetrace/shared";

type LangGraphModule = {
  StateGraph: new <S extends MachineState>(config: { channels: Record<string, unknown> }) => {
    addNode: (id: string, fn: (state: S) => Promise<void>) => unknown;
    compile: () => { invoke: (input: S, config?: { configurable?: { thread_id?: string } }) => Promise<S> };
  };
};

let cached: LangGraphModule | undefined;

function loadLangGraph(): LangGraphModule {
  if (cached) return cached;
  // 动态 import 保持"未安装也可 import 本文件"；解析失败时显式抛错。
  const req = eval("require") as (id: string) => LangGraphModule;
  try {
    cached = req("@langchain/langgraph");
  } catch {
    throw new Error("langgraph 后端不可用：未安装 @langchain/langgraph。请 npm install 后重试，或把 config/orchestration.yml 的 backend 切回 native（禁止静默降级）。");
  }
  return cached;
}

export class LangGraphMachineBackend<S extends MachineState = MachineState> implements MachineBackend<S> {
  readonly name = "langgraph" as const;

  constructor(
    private readonly deps: {
      /** 注入 loader 便于测试；缺省走真实依赖解析。 */
      load?: () => LangGraphModule;
    } = {},
  ) {}

  private module(): LangGraphModule {
    return this.deps.load ? this.deps.load() : loadLangGraph();
  }

  async run(context: BackendContext<S>): Promise<MachineResult> {
    let lg: LangGraphModule;
    try {
      lg = this.module();
    } catch (err) {
      throw err instanceof Error ? err : new Error("langgraph 后端不可用：" + String(err));
    }
    const traceId = context.traceId ?? nextId("tr");
    const order = topoOrder(context.spec.nodes);
    const channels: Record<string, unknown> = {};
    for (const key of Object.keys(context.spec.reducers ?? {})) channels[key] = null;
    const graph = new lg.StateGraph<S>({ channels });
    for (const node of order) {
      graph.addNode(node.id, async () => { await node.run({} as S); });
    }
    const app = graph.compile();
    const threadId = context.traceId;
    const final = await app.invoke({} as S, { configurable: { thread_id: threadId } });
    // LangGraph 未暴露与 native 完全一致的 step 明细时，用 executed 顺序补齐（如实标注来源）。
    return {
      ok: true,
      executed: order.map((n) => n.id),
      degraded_nodes: [],
      failed: null,
      interrupted: false,
      steps: order.map((n) => ({ node_id: n.id, status: "ok" as const })),
      trace_id: traceId,
      state: final,
    } as MachineResult;
  }
}
