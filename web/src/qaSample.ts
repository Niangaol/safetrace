/**
 * 演示态样例数据（供 `/qa?demo=1` 使用）。
 *
 * 目的：**让整页渲染可以在 1 秒内验收**，不必等一次真实问答（要 25–35s）。
 * 内容取自本仓一次真实问答的实测输出（deepseek-v4-pro，CVE-2026-31001 怎么修复），
 * 不是编的 —— 它是"渲染长什么样"的固定基准。
 *
 * 注意：这只是**渲染样例**，不代表系统当前状态；
 * 页面上会明确标注"演示样例"，避免被误当成真实运行结果（红线⑤ Mock 要说出口）。
 */
import type { ReasoningStep, StageStep, TraceStep } from './stores/qa'
import type { Citation } from './types'

export const SAMPLE_QUESTION = 'CVE-2026-31001 怎么修复？请给出具体版本和缓解措施。'

export const SAMPLE_ANSWER = `结论：
- 修复版本：将 vLLM 升级到 0.9.3 或更高版本 [S2]。
- 临时缓解措施：在反向代理层校验 chat_template 字段，拒绝包含双大括号且长度异常的请求 [S2]。
- 受影响范围：vLLM 0.9.2 及更早版本 [S1]。

依据：
- [S1] CVE-2026-31001：vLLM 的 OpenAI 兼容服务把 chat_template 交给未加沙箱的 Jinja2 渲染，
  构造器链可逃逸到 os.popen，攻击者以服务进程权限执行任意命令。CVSS 9.8，EPSS 0.87。
- [S2] 修复方式：0.9.3 起改用 SandboxedEnvironment 并禁用属性访问。

推理链：
- S1 指出受影响版本为 ≤0.9.2，根因是未沙箱化渲染 [S1]。
- S2 给出修复版本与临时缓解手段 [S2]。

建议动作：
1. 立即确认 vLLM 版本；若为 0.9.2 或更早，升级到 0.9.3 或更高版本 [S1][S2]。
2. 升级前在反向代理/WAF 增加规则，拒绝含双大括号且长度异常的 chat_template [S2]。`

/** 与上面对应的引用（url 为真实可点开的 NVD 详情页） */
export const SAMPLE_CITATIONS: Citation[] = [
  {
    id: 'S1',
    title: 'vuln:CVE-2026-31001',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-31001',
    score: 0,
    // 该漏洞的 VulnSource 含 nvd/ghsa（权威源）→ trusted
    trust: 'trusted',
    published_at: '2026-09-28T07:00:00+00:00',
  },
  {
    id: 'S2',
    title: 'vuln:CVE-2026-31001',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-31001',
    score: 0,
    trust: 'trusted',
    published_at: '2026-09-28T07:00:00+00:00',
  },
  {
    // 故意留一个**没有 trust/published_at** 的：样例要能展示契约要求的
    // "未评估 / 未知"这一档，否则验收时看不到缺省语义。
    id: 'S3',
    title: 'vuln:CVE-2026-28114',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-28114',
    score: 0,
  },
]

export const SAMPLE_REASONING: ReasoningStep[] = [
  { step: 1, sub_question: '识别与提问相关的漏洞', finding: '证据支持' },
  { step: 2, sub_question: '汇总其可利用性与影响面', finding: '证据支持' },
]

export const SAMPLE_STAGES: StageStep[] = [
  { stage: 'rewrite', message: '正在理解问题意图…' },
  { stage: 'retrieve', round: 1, hit: 0 },
  { stage: 'retrieve', round: 2, hit: 3 },
  { stage: 'generate', message: '基于 3 条证据生成答案…' },
  { stage: 'reasoning', message: '汇总推理链…' },
  { stage: 'check', message: '自检答案是否被证据支持…' },
  { stage: 'done', message: '完成：3 条引用' },
]

export const SAMPLE_META = {
  sessionId: 'sess_demo_sample',
  elapsedMs: 25190,
  model: 'deepseek-v4-pro',
  costCny: 0.0316,
  degraded: false,
  citationCount: 3,
}

/** 样例轨迹（时序与一次真实问答一致，便于验收"过程可视化"的排版） */
export const SAMPLE_TRACES: TraceStep[] = [
  {
    step: 'recv',
    tool: 'chat',
    input: { question: SAMPLE_QUESTION, top_k: 8 },
    startedAt: 0,
  },
  {
    step: 'plan',
    tool: 'QAAgent.plan',
    ok: true,
    output: '拆出 3 个子问题 / 4 条检索式',
    startedAt: 0,
    finishedAt: 3950,
    extra: {
      sub_questions: ['CVE-2026-31001 是否真实存在？', '其漏洞类型与受影响产品', '官方修复版本与缓解措施'],
      queries: ['CVE-2026-31001', 'CVE-2026-31001 patch fix security advisory'],
    },
  },
  {
    step: 'retrieve.1',
    tool: 'hybrid_search',
    input: { queries: ['CVE-2026-31001', 'CVE-2026-31001 patch fix'], top_k: 8, round: 1 },
    ok: true,
    output: '合并后 3 条，其中新增 3 条',
    startedAt: 3950,
    finishedAt: 3981,
    extra: { round: 1, fetched: 3, new: 3, total: 3 },
  },
  {
    step: 'retrieve.2',
    tool: 'hybrid_search',
    input: { queries: ['CVE-2026-31001', '混合检索补一轮'], top_k: 8, round: 2 },
    ok: true,
    output: '合并后 3 条，其中新增 0 条',
    startedAt: 3981,
    finishedAt: 3992,
    extra: { round: 2, fetched: 3, new: 0, total: 3 },
  },
  {
    step: 'citations',
    tool: 'build_evidence',
    ok: true,
    output: '整理出 3 条可引用证据',
    startedAt: 3992,
    finishedAt: 3992,
    extra: { citations: 3 },
  },
  {
    step: 'generate',
    tool: 'LLM.stream',
    ok: true,
    output: '生成 677 字',
    startedAt: 3992,
    finishedAt: 20869,
    extra: { chars: 677, model: 'deepseek-v4-pro' },
  },
  {
    step: 'reasoning',
    tool: 'build_chain',
    ok: true,
    output: '2 步推理',
    startedAt: 20869,
    finishedAt: 20869,
  },
  {
    step: 'check',
    tool: 'check_answer',
    ok: true,
    output: '自检通过（证据支持）',
    startedAt: 20869,
    finishedAt: 23926,
    extra: { score: 0.95 },
  },
]
