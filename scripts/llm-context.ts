import { readFile } from "node:fs/promises";
import { SqliteLlmContextStore } from "@safetrace/shared";
import type { LlmContextDefinition, LlmContextSetRecord } from "@safetrace/shared";

function summary(value: LlmContextSetRecord) {
  return {
    context_id: value.context_id, version: value.version, task_key: value.task_key, role: value.role,
    data_domain: value.data_domain, priority: value.priority, source: value.source, active: value.active,
    description: value.description,
    blocks: value.blocks.map((block) => ({ block_id: block.block_id, stability: block.stability, position: block.position, content_sha256: block.content_sha256 })),
  };
}
function usage(): string {
  return [
    "用法：npm run llm:context -- <list|show|put|activate|deactivate> [参数]",
    "  list                              列出版本/role/task/domain/hash，不输出正文",
    "  show <context_id> [version]       查看某版本的完整内容",
    "  put <context.json>                新建不可变版本并激活；省略 version 时自动递增",
    "  activate <context_id> <version>  切换到已有版本",
    "  deactivate <context_id>           停用该 context；相关显式 task 调用会 fail-closed",
    "SQLITE_PATH 未设置时使用 ./var/safetrace.sqlite。put JSON 需含 task_key、role、data_domain、description、blocks。",
  ].join("\n");
}
async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (!command || !["list", "show", "put", "activate", "deactivate"].includes(command)) throw new Error(usage());
  const store = new SqliteLlmContextStore();
  try {
    if (command === "list") {
      console.log(JSON.stringify(store.list(), null, 2));
      return;
    }
    if (command === "show") {
      const contextId = args[0];
      if (!contextId) throw new Error(usage());
      const version = args[1] === undefined ? undefined : Number(args[1]);
      if (version !== undefined && (!Number.isSafeInteger(version) || version < 1)) throw new Error("version must be a positive integer");
      const value = store.get(contextId, version);
      if (!value) throw new Error("context version not found");
      console.log(JSON.stringify(value, null, 2));
      return;
    }
    if (command === "put") {
      const path = args[0];
      if (!path) throw new Error(usage());
      const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("context JSON must be an object");
      const value = store.register(parsed as LlmContextDefinition, true);
      console.log(JSON.stringify({ registered: summary(value), prompt_text_printed: false }, null, 2));
      return;
    }
    if (command === "activate") {
      const contextId = args[0];
      const version = Number(args[1]);
      if (!contextId || !Number.isSafeInteger(version) || version < 1) throw new Error(usage());
      store.activate(contextId, version);
      console.log(JSON.stringify({ activated: contextId, version }));
      return;
    }
    const contextId = args[0];
    if (!contextId) throw new Error(usage());
    store.deactivate(contextId);
    console.log(JSON.stringify({ deactivated: contextId, explicit_task_calls: "fail-closed" }));
  } finally {
    store.close();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
