import type { InjectionFlag, InjectionGuard } from "./types.js";

/** Inputs are bounded so screening stays predictable and offline. */
const MAX_TEXTS = 128;
const MAX_TOTAL_CHARS = 100_000;

// These intentionally target strong instruction-like cues, not generic security terminology.
const INSTRUCTION_OVERRIDE: readonly RegExp[] = [
  /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+)?(?:(?:previous|prior|above|earlier|existing|current)\s+)?(?:(?:system|developer|safety)\s+)?(?:instructions?|rules?|prompts?|polic(?:y|ies)|guardrails?)\b/i,
  /\b(?:override|replace|disable)\s+(?:the\s+)?(?:system|developer|safety)\s+(?:prompt|instructions?|policy|rules?|guardrails?)\b/i,
  /(?:忽略|无视|忘记|作废)(?:掉)?(?:所有|全部|任何|之前|此前|先前|以上|上文|上述|当前|原有|既有|系统|开发者|安全|的)*(?:系统|开发者|安全)?(?:规则|指令|提示词?|策略|约束)/,
  /(?:覆盖|替换|绕过|禁用)(?:掉)?(?:当前|现有|原有|系统|开发者|安全)?(?:系统|开发者|安全)?(?:指令|提示词?|策略|规则|约束)/,
];

const FAKE_SYSTEM_PROMPT: readonly RegExp[] = [
  /<\|system\|>/i,
  /<system(?:\s[^>]*)?>/i,
  /(?:^|\n)\s*(?:#{1,6}\s*)?system\s+(?:prompt|message|instructions?)\s*[:：]/i,
  /(?:^|\n)\s*(?:#{1,6}\s*)?system\s*[:：]\s*(?:you are|ignore|disregard|override|reveal|do not|must)/i,
  /(?:^|\n)\s*(?:系统提示词?|系统消息|系统指令)\s*[:：]/,
];

const ROLE_CONFUSION: readonly RegExp[] = [
  /<\|(?:assistant|developer|user)\|>/i,
  /(?:^|\n)\s*(?:#{1,6}\s*)?(?:assistant|developer|user)\s*[:：]\s*(?:you are now|ignore|disregard|override|reveal|send|upload|do not|must)/i,
  /\b(?:you are now|from now on you are)\s+(?:an?\s+)?(?:unrestricted|uncensored|developer|system|root|admin)(?:\s+(?:assistant|model|agent))?\b/i,
  /(?:你现在是|从现在开始你是)(?:一个)?(?:不受限制|无审查|开发者|系统|管理员)(?:助手|模型|智能体)?/,
];

const EXFIL_INSTRUCTION: readonly RegExp[] = [
  /(?:^|[\n;:!?]\s*|\bplease\s+|\byou\s+(?:must|should|need to)\s+)(?:reveal|print|dump|send|upload|forward|exfiltrate|exfil|return|disclose|copy|email|post|read out)\s+(?:(?:all|the|your|my|any|every|hidden|internal|confidential)\s+)*(?:system\s+prompt|developer\s+prompt|secrets?|credentials?|api[-_ ]keys?|access tokens?|private keys?|passwords?|environment variables?)\b/i,
  /(?:泄露|披露|显示|输出|打印|读取|发送|上传|转发|导出|返回|窃取|复制)(?:出)?(?:所有|全部|你的|这些|该)?(?:系统提示词?|开发者提示词?|密钥|口令|令牌|凭证|机密|秘密|环境变量|密码|api[-_ ]?keys?|access tokens?|credentials?|secrets?|passwords?)/i,
];

const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/;
const BASE64_CUE = /\b(?:base64|b64)\s*[:=]\s*(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})/i;
const HTML_ENTITY_CUE = /(?:&\#(?:x[0-9a-f]{1,6}|[0-9]{1,7});){4,}|&lt;\s*(?:system|assistant|developer)\s*&gt;/i;
const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const COMMENT_INJECTION_CUE = /\b(?:ignore|disregard|forget|override|reveal|exfiltrate|credentials?|secrets?|api[-_ ]keys?|system\s+prompt|developer\s+prompt)\b|忽略|无视|忘记|覆盖|泄露|提示词|密钥|凭证/;
const CITATION_SPOOF: readonly RegExp[] = [
  /\[(?=[^\]]{0,120}\b(?:NIST|CISA|CERT|OpenAI|Anthropic|official|verified|administrator|system)\b)[^\]]{1,120}\]\s*(?:(?:official|verified|system|administrator)\s*)?(?:requires?|authorizes?|permits?|says?|confirms?)?\s*(?:ignore|disregard|override|reveal|send|upload|exfiltrate|\bmust\b|忽略|无视|覆盖|泄露|必须)/i,
  /(?:according to|per|as cited in)\s+\[[^\]]{1,120}\]\s*.{0,60}(?:ignore|disregard|override|reveal|send|upload|exfiltrate|忽略|无视|覆盖|泄露)/i,
  /据\s*\[[^\]]{1,120}(?:官方|权威|系统|管理|安全)[^\]]*\]\s*.{0,60}(?:忽略|无视|覆盖|泄露|必须)/,
];
const MULTI_STAGE: readonly RegExp[] = [
  /\b(?:first|step\s*1|phase\s*1|stage\s*1)\b[\s\S]{0,300}\b(?:then|next|after that|step\s*2|phase\s*2|stage\s*2)\b[\s\S]{0,240}\b(?:ignore|disregard|override|reveal|exfiltrate|send|upload|system prompt|secrets?|credentials?|api[-_ ]keys?)\b/i,
  /(?:首先|第一步|阶段一)[\s\S]{0,240}(?:然后|接着|之后|第二步|阶段二)[\s\S]{0,200}(?:忽略|无视|覆盖|泄露|输出|发送|上传|系统提示词?|密钥|凭证)/,
  /\bwhen (?:i|the user) (?:say|send|provide)\b[\s\S]{0,120}\b(?:then|after that)\b[\s\S]{0,120}\b(?:ignore|reveal|send|upload|system prompt|secrets?|credentials?)\b/i,
  /等我(?:说|发送|提供).{0,100}(?:再|之后|然后).{0,100}(?:忽略|无视|泄露|输出|发送|系统提示词|密钥)/,
];

const matchesAny = (text: string, patterns: readonly RegExp[]): boolean => patterns.some((pattern) => pattern.test(text));

type InjectionScreenResult = Pick<InjectionGuard, "screened" | "note"> & {
  allowed: boolean;
  max_score: number;
  flags: InjectionFlag[];
};

const invalidResult = (): InjectionScreenResult => ({
  screened: false,
  allowed: false,
  max_score: 1,
  flags: [],
  note: "Input was empty, invalid, or over the screening limit; denied without screening.",
});

/**
 * Deterministic, offline heuristic only: a clean result is not a guarantee.
 * Callers must still require trusted public scope; this function never grants trust.
 */
export function screenPromptInjection(texts: readonly string[]): InjectionScreenResult {
  try {
    if (!Array.isArray(texts) || texts.length === 0 || texts.length > MAX_TEXTS) return invalidResult();
    let totalChars = 0;
    let hasNonWhitespace = false;
    for (const text of texts) {
      if (typeof text !== "string") return invalidResult();
      totalChars += text.length;
      if (totalChars > MAX_TOTAL_CHARS) return invalidResult();
      if (text.trim().length > 0) hasNonWhitespace = true;
    }
    if (!hasNonWhitespace) return invalidResult();

    const combined = texts.join("\n");
    const normalized = combined.normalize("NFKC");
    const flags = new Set<InjectionFlag>();
    if (matchesAny(normalized, INSTRUCTION_OVERRIDE)) flags.add("instruction_override");
    if (matchesAny(normalized, FAKE_SYSTEM_PROMPT)) flags.add("fake_system_prompt");
    if (matchesAny(normalized, ROLE_CONFUSION)) flags.add("role_confusion");
    if (matchesAny(normalized, EXFIL_INSTRUCTION)) flags.add("exfil_instruction");
    if (ZERO_WIDTH.test(combined)) flags.add("zero_width_chars");
    if (BASE64_CUE.test(normalized)) flags.add("base64_hidden");
    if (HTML_ENTITY_CUE.test(normalized)) flags.add("html_entity_encoded");
    for (const match of combined.matchAll(HTML_COMMENT)) {
      if (COMMENT_INJECTION_CUE.test(match[1] ?? "")) flags.add("comment_embedded");
    }
    if (matchesAny(normalized, CITATION_SPOOF)) flags.add("citation_spoof");
    if (matchesAny(normalized, MULTI_STAGE)) flags.add("multi_stage");

    const sortedFlags = [...flags].sort();
    const suspicious = sortedFlags.length > 0;
    return {
      screened: true,
      allowed: !suspicious,
      max_score: suspicious ? 1 : 0,
      flags: sortedFlags,
      note: suspicious
        ? "Potential prompt-injection signals were detected; denied. Heuristic screening is not a guarantee."
        : "No configured signals matched. Heuristic screening is not a guarantee; callers must require trusted public scope.",
    };
  } catch {
    // Never echo input or exception details; malformed runtime values fail closed.
    return invalidResult();
  }
}
