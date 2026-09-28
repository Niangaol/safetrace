/**
 * 四 Agent 角色定义（对齐 contracts/events.md 主题表）。
 * 每个角色：职责 + 独占主题（生产者/消费者边界）+ 工具白名单（越权即缺陷）。
 */
import type { Topic } from "@safetrace/shared";

export type AgentRoleName = "monitor" | "enricher" | "qa" | "selfheal";

export interface AgentRole {
  name: AgentRoleName;
  /** 中文展示名（含所属线，便于看板与汇报） */
  title: string;
  duties: string[];
  /** 独占主题：只有该角色允许生产这些主题的事件 */
  exclusive_topics: Topic[];
  /** 工具白名单：MCP 注册与权限校验的依据 */
  tools: string[];
}

export const AGENT_ROLES: Record<AgentRoleName, AgentRole> = {
  monitor: {
    name: "monitor",
    title: "监测 Agent（Y 线）",
    duties: ["按源订阅计划抓取 RawDoc（NVD/cve.org/KEV/OSV/arXiv/EPSS）", "external_id 幂等回放，断点续抓", "源健康检查、限流退避与 fixture 回放"],
    exclusive_topics: ["raw.docs"],
    tools: ["source_adapter", "http_fetch", "fixture_replay"],
  },
  enricher: {
    name: "enricher",
    title: "富化 Agent（F 线）",
    duties: ["按 TriageOrder 派发维度任务（paper/asset/poc/cvss/remediation/triage）", "产出 EnrichmentResult 与论文关联", "质量分与 verdict 写入 DQ1"],
    exclusive_topics: ["intel.items", "enrich.triage", "enrich.papers", "enrich.items", "dq.verdicts"],
    tools: ["enrich_dimension", "paper_linker", "scorer", "retriever"],
  },
  qa: {
    name: "qa",
    title: "问答 Agent（Q 线）",
    duties: ["Q1 意图识别与槽位抽取（低置信度走澄清）", "Q2 跨文档检索取证据包（引用可回溯）", "Q4 四段式作答，证据不足拒答"],
    exclusive_topics: ["qa.queries", "qa.answers"],
    tools: ["intent_classifier", "retriever", "answer_synthesizer"],
  },
  selfheal: {
    name: "selfheal",
    title: "自愈 Agent（A 线）",
    duties: ["订阅 fallback.events 登记全部降级（兜底透明率 100% 证据源）", "死信重放与恢复验证", "健康看板数据供给"],
    exclusive_topics: ["fallback.events"],
    tools: ["replay", "dead_letter_drain", "healthcheck"],
  },
};

export function getRole(name: AgentRoleName): AgentRole {
  const role = AGENT_ROLES[name];
  if (!role) throw new Error("未知角色：" + name);
  return role;
}
