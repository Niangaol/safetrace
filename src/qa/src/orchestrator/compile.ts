/**
 * A-01 compile()：把 MachineSpec 编译成可执行计划。
 *
 * 历史：曾支持 native / langgraph 双后端。langgraph 分支已于 2026-09-30 删除——
 * @langchain/langgraph 从未进入 package.json，4 个对应用例永久 skip，属死代码；
 * 保留它只会让"配置写错时该报什么错"多一条无人验证过的路径。
 * 现在只有 native 一个后端（自研顺序执行器，零外部依赖，保 main 可演示）。
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { MachineBackend, MachineSpec, MachineState } from "./statemachine.js";
import { NativeMachineBackend } from "./backends/native.js";
import { validateSpec } from "./statemachine.js";

/** 正则片段：空白（用 RegExp 构造避免源码转义层数问题）。 */
const re = String.fromCharCode(92) + "s";

export interface OrchestrationConfig {
  backend: "native";
  interrupts: { enabled: boolean; node_id: string | null };
}

export function loadOrchestrationConfig(path = resolve("config/orchestration.yml")): OrchestrationConfig {
  const text = readFileSync(path, "utf8");
  const backend = text.match(new RegExp("^backend:" + re + "([^ " + re + "]+)", "m"))?.[1];
  if (backend !== "native") {
    throw new Error("config/orchestration.yml 的 backend 必须是 native（当前：" + String(backend) + "）");
  }
  const enabled = new RegExp("^" + re + "*enabled:" + re + "*true", "m").test(text);
  const nodeId = text.match(new RegExp("^" + re + "*node_id:" + re + "*([^ " + re + "]+)", "m"))?.[1];
  return { backend, interrupts: { enabled, node_id: nodeId && nodeId !== "null" ? nodeId : null } };
}

export interface CompiledMachine<S extends MachineState = MachineState> {
  config: OrchestrationConfig;
  backend: MachineBackend<S>;
}

/** 编译并返回后端。编译期即校验 spec：配置错误（成环等）必须在启动时暴露，不拖到运行期。 */
export function compile<S extends MachineState = MachineState>(
  _spec: MachineSpec<S>,
  opts: { config?: OrchestrationConfig } = {},
): CompiledMachine<S> {
  const config = opts.config ?? loadOrchestrationConfig();
  // 注入的 config 可能是测试/调用方用 as never 强转来的，类型系统拦不住；
  // 运行时仍要按同一口径校验，否则非法 backend 会被静默放过。
  if (config.backend !== "native") {
    throw new Error("config 的 backend 必须是 native（当前：" + String(config.backend) + "）");
  }
  validateSpec(_spec.nodes);
  return {
    config,
    backend: new NativeMachineBackend<S>({ interruptAt: config.interrupts.enabled ? config.interrupts.node_id ?? undefined : undefined }),
  };
}
