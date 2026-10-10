/**
 * Q1 意图识别：QueryTurn → QueryPlan（关键词 + 权重打分，纯规则，零 LLM，离线可跑）。
 * 纪律：禁止猜测——打分低于阈值时 needs_clarify=true 并给出澄清问题，交由用户补齐。
 */
import type { QueryTurn } from "@safetrace/shared";

/** 意图种类（对齐 02-report Q 线契约）。 */
export type IntentKind =
  | "impact_range"   // 影响范围 / 受影响版本
  | "remediation"    // 修复 / 补丁 / 缓解
  | "attack_chain"   // 攻击链 / 利用步骤
  | "trend"          // 趋势 / 统计
  | "concept"        // 概念 / 原理解释
  | "paper_related"; // 学术论文关联

/** 检索策略。 */
export type QueryStrategy = "fact_lookup" | "multi_hop" | "timeline" | "attack_chain" | "recommend";

export interface QuerySlots {
  cve_ids: string[];
  products: string[];
  versions: string[];
  /** 归一化时间窗：7d / 30d / 90d / 1y / ytd；未提及为 null */
  time_range: string | null;
}

export interface QueryPlan {
  /** 主意图在前；与榜首分差 <40% 的次意图并入（多意图问题常见） */
  intents: IntentKind[];
  slots: QuerySlots;
  strategy: QueryStrategy;
  /** 槽位补全后的检索用文本（QueryTurn 原文 + 机器可读槽位后缀） */
  rewrite_text: string;
  needs_clarify: boolean;
  clarify_question?: string;
  /** 0-1 启发式分值（非校准概率）；由规则或经校验的 StepPlan 辅助分类产生。 */
  confidence: number;
  classifier_source?: "rules" | "stepplan";
}

/** 关键词 → 权重表。权重按领域先验设定：术语（攻击链/论文）重于泛化词。 */
const INTENT_KEYWORDS: Record<IntentKind, ReadonlyArray<readonly [string, number]>> = {
  impact_range: [["影响范围", 4], ["哪些版本", 3], ["受影响", 3], ["影响", 2], ["范围", 2], ["affected", 3], ["impact", 2]],
  remediation: [
    ["如何修复", 4], ["怎么修复", 3], ["怎么修", 3], ["修复", 3], ["补丁", 3], ["如何缓解", 4],
    ["缓解", 3], ["升级", 2], ["解决方案", 3], ["fix", 2], ["patch", 3], ["mitigate", 2],
  ],
  attack_chain: [["攻击链", 4], ["攻击路径", 4], ["攻击步骤", 3], ["攻击者", 2], ["kill chain", 4], ["exploit chain", 4], ["回连", 2]],
  trend: [["趋势", 4], ["统计", 3], ["增长", 3], ["热点", 3], ["热度", 3], ["数量", 2], ["排名", 2], ["近期", 2], ["最近", 2], ["trend", 3]],
  concept: [["是什么", 4], ["什么是", 4], ["原理", 3], ["概念", 4], ["定义", 3], ["介绍", 2], ["what is", 4]],
  paper_related: [["论文", 5], ["文献", 4], ["学术", 3], ["paper", 4], ["arxiv", 4], ["研究进展", 3]],
};

/** 意图 → 默认检索策略。 */
const STRATEGY_BY_INTENT: Record<IntentKind, QueryStrategy> = {
  impact_range: "fact_lookup",
  remediation: "recommend",
  attack_chain: "attack_chain",
  trend: "timeline",
  concept: "multi_hop",
  paper_related: "multi_hop",
};

export function strategyForIntent(intent: IntentKind): QueryStrategy {
  return STRATEGY_BY_INTENT[intent];
}

/**
 * A-05：时间窗代码 → published_after 截止时间（ISO-8601 UTC）。
 * 识别不了的代码返回 null（不猜时间）；ytd = 今年 1 月 1 日（UTC）。
 * 与 q2-retrieval 的 published_after 过滤配套："最近 7 天"从此是硬检索条件，
 * 不再只是 rewrite_text 里的装饰后缀。
 */
export function publishedAfterFor(timeRange: string, now: Date): string | null {
  const DAY_MS = 86_400_000;
  switch (timeRange) {
    case "7d": return new Date(now.getTime() - 7 * DAY_MS).toISOString();
    case "30d": return new Date(now.getTime() - 30 * DAY_MS).toISOString();
    case "90d": return new Date(now.getTime() - 90 * DAY_MS).toISOString();
    case "1y": return new Date(now.getTime() - 365 * DAY_MS).toISOString();
    case "ytd": return new Date(Date.UTC(now.getUTCFullYear(), 0, 1)).toISOString();
    default: return null;
  }
}

/**
 * A-05：意图时效阈值（天）。趋势/KEV 动态类问题要新（≤7d）；影响范围类放宽到 90d；
 * 其余意图与未识别意图维持 365d 默认（与 q4-answer 的 DEFAULT_STALE_THRESHOLD_DAYS 同口径）。
 * KEV 动态类提问含"最近/热点/近期"等词，按关键词表落入 trend，因此不单列 KEV 意图。
 */
export const STALE_THRESHOLD_DAYS_BY_INTENT: Readonly<Partial<Record<IntentKind, number>>> = {
  trend: 7,
  impact_range: 90,
};

export const DEFAULT_INTENT_STALE_THRESHOLD_DAYS = 365;

/** 主意图优先取阈值；多意图时取榜单第一个有配置的意图（最严口径）。 */
export function staleThresholdDays(plan: QueryPlan): number {
  for (const intent of plan.intents) {
    const days = STALE_THRESHOLD_DAYS_BY_INTENT[intent];
    if (days !== undefined) return days;
  }
  return DEFAULT_INTENT_STALE_THRESHOLD_DAYS;
}

/** 产品词典：[规范名, 别名...]；别名命中即归一到规范名。 */
const PRODUCT_DICT: ReadonlyArray<readonly [string, ...string[]]> = [
  ["log4j", "log4shell", "log4j2", "log4j-core"],
  ["ollama"],
  ["apache", "apache http server", "httpd"],
  ["nginx"],
  ["redis"],
  ["openssl"],
  ["spring", "spring4shell", "spring framework", "springboot", "spring boot"],
  ["openssh"],
  ["fastjson"],
  ["shiro"],
  ["tomcat"],
  ["mysql"],
  ["linux kernel", "linux"],
  ["wordpress"],
  ["jenkins"],
  ["gitlab"],
  ["confluence"],
  ["struts"],
  ["weblogic"],
  ["kubernetes", "k8s"],
  ["docker"],
];

/** 时间表述 → 归一化时间窗（长周期在前，避免「近一年」被「月」抢先）。 */
const TIME_RANGE_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  [/(?:最近|近)\s*一?年|一年内|过去一年/, "1y"],
  [/(?:最近|近)\s*三?个?月|90\s*天|过去三个月/, "90d"],
  [/(?:最近|近)\s*一?个?月|30\s*天|过去一个月/, "30d"],
  [/(?:最近|近)\s*一?周|7\s*天|过去一周/, "7d"],
  [/今年|年初以来/, "ytd"],
];

/** 榜首得分低于该值 → 意图不明确，必须澄清（禁止硬猜）。 */
const CLARIFY_THRESHOLD = 2;
/** 次意图并入阈值：≥ 榜首 60%。 */
const SECOND_INTENT_RATIO = 0.6;

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const VERSION_RE = /\b[vV]?(\d+(?:\.\d+){1,3}(?:-(?:beta|rc|alpha)\d*)?)\b/g;

function countOccurrences(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  let n = 0;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    n += 1;
    idx = haystack.indexOf(needle, idx + needle.length);
  }
  return n;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function extractSlots(text: string): QuerySlots {
  const lower = text.toLowerCase();
  const cve_ids = dedupe((text.match(CVE_RE) ?? []).map((s) => s.toUpperCase()));
  const products: string[] = [];
  for (const [canonical, ...aliases] of PRODUCT_DICT) {
    if (aliases.some((a) => lower.includes(a)) || lower.includes(canonical)) products.push(canonical);
  }
  const versions = dedupe((text.match(VERSION_RE) ?? []).map((m) => m.replace(/^[vV]/, "")));
  let time_range: string | null = null;
  for (const [re, code] of TIME_RANGE_RULES) {
    if (re.test(text)) { time_range = code; break; }
  }
  return { cve_ids, products, versions, time_range };
}

function buildRewrite(text: string, slots: QuerySlots): string {
  const parts: string[] = [];
  if (slots.cve_ids.length > 0) parts.push(`CVE=${slots.cve_ids.join(",")}`);
  if (slots.products.length > 0) parts.push(`product=${slots.products.join(",")}`);
  if (slots.versions.length > 0) parts.push(`version=${slots.versions.join(",")}`);
  if (slots.time_range) parts.push(`time=${slots.time_range}`);
  return parts.length > 0 ? `${text} [槽位补全: ${parts.join("; ")}]` : text;
}

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

/**
 * 规则意图分类。返回的 QueryPlan 直接驱动 Q2 检索与 Q4 作答；
 * 置信度不足时调用方应优先走澄清而不是检索（见 needs_clarify）。
 */
export function classifyIntent(turn: QueryTurn): QueryPlan {
  const text = turn.text ?? "";
  const lower = text.toLowerCase();
  const slots = extractSlots(text);

  const scores = {} as Record<IntentKind, number>;
  for (const kind of Object.keys(INTENT_KEYWORDS) as IntentKind[]) {
    let s = 0;
    for (const [kw, w] of INTENT_KEYWORDS[kind]) s += countOccurrences(lower, kw) * w;
    scores[kind] = s;
  }
  const ranked = (Object.keys(scores) as IntentKind[]).sort(
    (a, b) => (scores[b] ?? 0) - (scores[a] ?? 0) || a.localeCompare(b),
  );

  const topKind = ranked[0];
  const topScore = topKind ? (scores[topKind] ?? 0) : 0;
  const secondKind = ranked[1];
  const secondScore = secondKind ? (scores[secondKind] ?? 0) : 0;

  const intents: IntentKind[] = [];
  if (topKind && topScore >= CLARIFY_THRESHOLD) {
    intents.push(topKind);
    if (secondKind && secondScore > 0 && secondScore >= topScore * SECOND_INTENT_RATIO) intents.push(secondKind);
  }

  const needs_clarify = topScore < CLARIFY_THRESHOLD;
  const clarify_question = needs_clarify
    ? "没能确定你想了解的角度：请补充漏洞编号（如 CVE-2021-44228）或产品名，并说明关注影响范围、修复方式、攻击手法还是研究趋势？"
    : undefined;

  // 置信度：得分绝对值（饱和到 8 分）与榜首区分度各占一半
  const separation = secondScore > 0 ? 1 - secondScore / topScore : 1;
  const confidence = topScore > 0 ? Math.round(clamp01(0.6 * Math.min(1, topScore / 8) + 0.4 * separation) * 100) / 100 : 0;

  const strategy: QueryStrategy =
    slots.cve_ids.length >= 2 ? "multi_hop" : intents.length > 0 ? STRATEGY_BY_INTENT[intents[0]!] : "fact_lookup";

  return {
    intents,
    slots,
    strategy,
    rewrite_text: buildRewrite(text, slots),
    needs_clarify,
    ...(clarify_question ? { clarify_question } : {}),
    confidence,
    classifier_source: "rules",
  };
}
