/**
 * A-01 compile()：把 MachineSpec 编译成可执行计划，并按配置选择后端。
 * 缺省 native；显式选 langgraph 但依赖不可用时抛错（不静默降级）。
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { MachineBackend, MachineSpec, MachineState } from "./statemachine.js";
import { NativeMachineBackend } from "./backends/native.js";
import { validateSpec } from "./statemachine.js";
import { LangGraphMachineBackend } from "./backends/langgraph.js";

/** 正则片段：空白（用 RegExp 构造避免源码转义层数问题）。 */
const re = String.fromCharCode(92) + "s";

export interface OrchestrationConfig {
  backend: "native" | "langgraph";
  interrupts: { enabled: boolean; node_id: string | null };
}

export function loadOrchestrationConfig(path = resolve("config/orchestration.yml")): OrchestrationConfig {
  const text = readFileSync(path, "utf8");
  const backend = text.match(new RegExp("^backend:" + re + "(\\S+)", "m"))?.[1];
  if (backend !== "native" && backend !== "langgraph") {
    throw new Error("config/orchestration.yml 的 backend 必须是 native 或 langgraph（当前：" + String(backend) + "）");
  }
  const enabled = new RegExp("^" + re + "*enabled:" + re + "*true", "m").test(text);
  const nodeId = text.match(new RegExp("^" + re + "*node_id:" + re + "*(\\S+)", "m"))?.[1];
  return { backend, interrupts: { enabled, node_id: nodeId && nodeId !== "null" ? nodeId : null } };
}

export interface CompiledMachine<S extends MachineState = MachineState> {
  config: OrchestrationConfig;
  backend: MachineBackend<S>;
}

/** 选择后端。langgraph 不可用时抛错，由调用方显式处理（禁静默降级）。 */
export function compile<S extends MachineState = MachineState>(
  _spec: MachineSpec<S>,
  opts: { config?: OrchestrationConfig; langgraphLoader?: () => unknown } = {},
): CompiledMachine<S> {
  const config = opts.config ?? loadOrchestrationConfig();
  // 编译期即校验 spec：配置错误（缺依赖/成环）必须在启动时暴露，不拖到运行期。
  validateSpec(_spec.nodes);
  if (config.backend !== "native" && config.backend !== "langgraph") {
    throw new Error("config/orchestration.yml 的 backend 必须是 native 或 langgraph（当前：" + String(config.backend) + "）");
  }
  if (config.backend === "langgraph") {
    return {
      config,
      backend: new LangGraphMachineBackend<S>({ load: opts.langgraphLoader as never }),
    };
  }
  return {
    config,
    backend: new NativeMachineBackend<S>({ interruptAt: config.interrupts.enabled ? config.interrupts.node_id ?? undefined : undefined }),
  };
}
