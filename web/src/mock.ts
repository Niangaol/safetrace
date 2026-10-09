import type {
  CollectStatus,
  EvidenceResponse,
  MetricsOverview,
  Paged,
  VulnItem,
} from './types'
import type { AssetAlert, AssetComponent, AssetRepo, AssetsOverview, AssetsScanResult } from './api'

export const mockMetrics: MetricsOverview = {
  collect: { raw_items: 5230, vulns: 1284, merge_ratio: 0.754, sources: 7 },
  latency: { p50_seconds: 6300, p95_seconds: 19800, sla_6h_ratio: 0.71 },
  enrich: {
    coverage_ratio: 0.96,
    records: 1233,
    dimensions: 7,
    degraded_ratio: 0.08,
    per_dimension: {
      paper: { records: 924, coverage_ratio: 0.72, confidence_avg: 0.68, degraded_ratio: 0.0, mock_ratio: 1.0 },
      asset: { records: 1220, coverage_ratio: 0.95, confidence_avg: 0.5, degraded_ratio: 1.0, mock_ratio: 1.0 },
      poc: { records: 783, coverage_ratio: 0.61, confidence_avg: 0.77, degraded_ratio: 0.12, mock_ratio: 1.0 },
      cvss: { records: 1258, coverage_ratio: 0.98, confidence_avg: 0.88, degraded_ratio: 0.0, mock_ratio: 1.0 },
      fix: { records: 1066, coverage_ratio: 0.83, confidence_avg: 0.79, degraded_ratio: 0.15, mock_ratio: 1.0 },
      consistency: { records: 1206, coverage_ratio: 0.94, confidence_avg: 0.85, degraded_ratio: 0.06, mock_ratio: 1.0 },
      ai_risk: { records: 1245, coverage_ratio: 0.97, confidence_avg: 0.75, degraded_ratio: 0.02, mock_ratio: 1.0 },
    },
  },
  knowledge: { chunks: 8492 },
  agents: { runs: 86, failed: 3 },
  cost: { total_cny: 62.4, daily_budget_cny: 20.0, degraded: false, breakdown: { deepseek: 48.2, local: 14.2 } },
}

export const mockCollectStatus: CollectStatus = {
  watermarks: [
    { source: 'nvd', last_sync_at: '2026-09-29T09:30:00+08:00', last_full_sync_at: '2026-09-28T03:00:00+08:00', last_published_at: '2026-09-29T08:10:00+08:00', items_last_run: 42, success: true, error: null },
    { source: 'ghsa', last_sync_at: '2026-09-29T09:25:00+08:00', last_full_sync_at: '2026-09-27T22:00:00+08:00', last_published_at: '2026-09-29T07:45:00+08:00', items_last_run: 18, success: true, error: null },
    { source: 'arxiv', last_sync_at: '2026-09-29T08:00:00+08:00', last_full_sync_at: '2026-09-29T08:00:00+08:00', last_published_at: '2026-09-29T06:30:00+08:00', items_last_run: 7, success: true, error: null },
    { source: 'community_rss', last_sync_at: '2026-09-29T09:15:00+08:00', last_full_sync_at: '2026-09-28T12:00:00+08:00', last_published_at: '2026-09-29T09:02:00+08:00', items_last_run: 23, success: true, error: null },
    { source: 'kev', last_sync_at: '2026-09-29T06:00:00+08:00', last_full_sync_at: '2026-09-29T06:00:00+08:00', last_published_at: '2026-09-28T18:00:00+08:00', items_last_run: 3, success: true, error: null },
    { source: 'osv', last_sync_at: '2026-09-29T09:20:00+08:00', last_full_sync_at: null, last_published_at: '2026-09-29T08:50:00+08:00', items_last_run: 12, success: true, error: null },
    { source: 'vulncheck', last_sync_at: null, last_full_sync_at: null, last_published_at: null, items_last_run: 0, success: false, error: 'API key expired' },
  ],
  queue_depth: 5,
}

const vulns: VulnItem[] = [
  {
    id: 'v_01JARXV', cve_id: 'CVE-2026-12345', ghsa_id: 'GHSA-x7v2-m3q8-wp9c',
    title: 'vLLM 远程代码执行漏洞（API 注入）', severity: 'critical', cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe: ['CWE-78', 'CWE-94'], cpe: ['cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'ai_infrastructure', exploit_status: 'poc_available',
    published_at: '2026-09-20T08:00:00+08:00', fetched_at: '2026-09-20T10:12:00+08:00',
    collect_latency_seconds: 7920, source_count: 4, enriched: true,
    summary: '攻击者通过构造特定的 API 请求，可在 vLLM 推理服务器上执行任意代码。影响所有未打补丁的 vLLM < 0.6.2 实例。',
  },
  {
    id: 'v_01JBRYP', cve_id: 'CVE-2026-12344', ghsa_id: 'GHSA-q3f5-8r2c-w6t7',
    title: 'LangChain SSRF 漏洞（工具链注入）', severity: 'high', cvss_score: 8.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    cwe: ['CWE-918'], cpe: ['cpe:2.3:a:langchain:langchain:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'ai_framework', exploit_status: 'patched',
    published_at: '2026-09-22T14:30:00+08:00', fetched_at: '2026-09-22T15:00:00+08:00',
    collect_latency_seconds: 1800, source_count: 3, enriched: true,
    summary: 'LangChain 自定义工具链存在 SSRF 缺陷，攻击者可借此访问内网资源。',
  },
  {
    id: 'v_01JCTZA', cve_id: 'CVE-2026-12343', ghsa_id: null,
    title: 'Transformers pickle 反序列化漏洞', severity: 'critical', cvss_score: 9.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe: ['CWE-502'], cpe: ['cpe:2.3:a:huggingface:transformers:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'model_supply_chain', exploit_status: 'exploit_available',
    published_at: '2026-09-25T09:00:00+08:00', fetched_at: '2026-09-25T09:30:00+08:00',
    collect_latency_seconds: 1800, source_count: 5, enriched: true,
    summary: '加载恶意构造的模型权重文件可导致 RCE，影响所有使用 from_pretrained 的场景。',
  },
  {
    id: 'v_01JDTZB', cve_id: 'CVE-2026-12342', ghsa_id: 'GHSA-m8n4-q6r2-v5t3',
    title: 'Ollama 模型加载路径穿越', severity: 'high', cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
    cwe: ['CWE-22'], cpe: ['cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'ai_infrastructure', exploit_status: 'poc_available',
    published_at: '2026-09-26T11:20:00+08:00', fetched_at: '2026-09-26T11:25:00+08:00',
    collect_latency_seconds: 300, source_count: 2, enriched: false,
    summary: '通过构造模型文件路径，攻击者可读取 Ollama 服务器上任意文件。',
  },
  {
    id: 'v_01JETZC', cve_id: 'CVE-2026-12341', ghsa_id: null,
    title: 'PyTorch torch.load 任意代码执行', severity: 'critical', cvss_score: 9.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwe: ['CWE-502', 'CWE-94'], cpe: ['cpe:2.3:a:pytorch:pytorch:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'model_supply_chain', exploit_status: 'exploit_available',
    published_at: '2026-09-27T16:00:00+08:00', fetched_at: '2026-09-27T16:05:00+08:00',
    collect_latency_seconds: 300, source_count: 4, enriched: true,
    summary: 'torch.load 在加载 .pt 文件时执行嵌入的 pickle 代码，导致 RCE。',
  },
  {
    id: 'v_01JFTZD', cve_id: 'CVE-2026-12340', ghsa_id: 'GHSA-k9p3-v7w4-m2x8',
    title: 'OpenAI Whisper 提示注入漏洞', severity: 'medium', cvss_score: 5.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    cwe: ['CWE-74'], cpe: ['cpe:2.3:a:openai:whisper:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'prompt_injection', exploit_status: null,
    published_at: '2026-09-28T08:30:00+08:00', fetched_at: '2026-09-28T08:35:00+08:00',
    collect_latency_seconds: 300, source_count: 2, enriched: false,
    summary: '通过音频中嵌入的语音指令可触发 Whisper 输出恶意文本，间接影响下游 LLM。',
  },
  {
    id: 'v_01JGTZE', cve_id: 'CVE-2026-12339', ghsa_id: null,
    title: 'LlamaIndex 文档加载器 SSRF', severity: 'medium', cvss_score: 4.9,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    cwe: ['CWE-918'], cpe: ['cpe:2.3:a:llamaindex:llamaindex:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'ai_framework', exploit_status: null,
    published_at: '2026-09-28T10:00:00+08:00', fetched_at: '2026-09-28T10:10:00+08:00',
    collect_latency_seconds: 600, source_count: 1, enriched: false,
    summary: '自定义 URL 文档加载器未做 SSRF 防护，可被用于内网探测。',
  },
  {
    id: 'v_01JHTZF', cve_id: 'CVE-2026-12338', ghsa_id: 'GHSA-p4q5-9r1s-w7t2',
    title: 'Hugging Face Hub 模型投毒', severity: 'high', cvss_score: 7.7,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
    cwe: ['CWE-502'], cpe: ['cpe:2.3:a:huggingface:hub:*:*:*:*:*:*:*:*'],
    ai_risk_category: 'model_supply_chain', exploit_status: 'patched',
    published_at: '2026-09-29T02:00:00+08:00', fetched_at: '2026-09-29T02:15:00+08:00',
    collect_latency_seconds: 900, source_count: 3, enriched: true,
    summary: '恶意上传的模型文件在被下载加载时可执行嵌入代码，影响下游所有使用者。',
  },
]

export function mockVulnsPage(params?: Record<string, string | number | boolean | undefined>): Paged<VulnItem> {
  let filtered = [...vulns]
  const q = (params?.q as string)?.toLowerCase()
  if (q) filtered = filtered.filter(v => v.title.toLowerCase().includes(q) || v.cve_id.toLowerCase().includes(q))
  const sev = params?.severity as string
  if (sev) filtered = filtered.filter(v => v.severity === sev)
  if (params?.has_poc === 'true') filtered = filtered.filter(v => v.exploit_status === 'poc_available' || v.exploit_status === 'exploit_available')
  const sort = params?.sort as string
  if (sort === 'cvss_score') filtered.sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
  else if (sort === 'fetched_at') filtered.sort((a, b) => (b.fetched_at ?? '').localeCompare(a.fetched_at ?? ''))
  else filtered.sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''))
  return { items: filtered, total: filtered.length, page: Number(params?.page ?? 1), page_size: Number(params?.page_size ?? 20) }
}

export function mockVuln(id: string): VulnItem {
  return vulns.find(v => v.id === id || v.cve_id === id) ?? vulns[0]
}

export function mockEvidence(id: string): EvidenceResponse {
  const v = mockVuln(id)
  const enrichments = []
  const dims = [
    { dimension: 'ai_risk', value: { category: v.ai_risk_category, attack_surface: 'API', mitre_attack: ['T1059.009', 'T1190'] }, confidence: 0.92, source: ['nvd', 'ghsa'], evidence: [{ source: 'nvd', url: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`, snippet: `AI 风险分类: ${v.ai_risk_category}，攻击面 API。映射 MITRE ATT&CK T1059.009 (Cloud API), T1190 (Exploit Public-Facing Application)。`, fetched_at: '2026-09-25T03:20:00+08:00' }] },
    { dimension: 'cvss', value: { score: v.cvss_score, vector: v.cvss_vector, severity: v.severity, impact: '保密性/完整性/可用性 全面受损' }, confidence: 0.99, source: ['nvd'], evidence: [{ source: 'nvd', url: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`, snippet: `CVSS v3.1 基础分 ${v.cvss_score}，向量 ${v.cvss_vector}。`, fetched_at: '2026-09-25T03:20:00+08:00' }] },
    { dimension: 'poc', value: { repo: `https://github.com/poc-corp/${v.cve_id.toLowerCase()}`, language: 'Python', verified: true, tier: 'confirmed', runtime_verified: false }, confidence: 0.86, source: ['github', 'nvd'], evidence: [{ source: 'github', url: `https://github.com/poc-corp/${v.cve_id.toLowerCase()}`, snippet: `# PoC for ${v.cve_id}\nimport requests; requests.post(url, json={"model": "__import__(\\"os\\").system(\\"id\\")"})`, fetched_at: '2026-09-25T03:20:00+08:00' }] },
    { dimension: 'paper', value: { title: 'Adversarial Attacks on LLM Serving Frameworks', arxiv_id: '2510.01234', relevance: 0.81 }, confidence: 0.75, source: ['arxiv'], evidence: [{ source: 'arxiv', url: 'https://arxiv.org/abs/2510.01234', snippet: '本文研究了 LLM 推理框架中的 API 注入攻击，分析了 vLLM 和 TGI 等框架的安全缺陷。', fetched_at: '2026-09-25T03:20:00+08:00' }] },
    { dimension: 'asset', value: { products: [{ name: 'vLLM', vendor: 'vllm-project', range: '< 0.6.2', fixed_version: '0.6.2' }], exposure: 'public_network' }, confidence: 0.5, source: ['nvd', 'cpe'], evidence: [{ source: 'cpe', url: null, snippet: `受影响 CPE: ${v.cpe.join(', ')}`, fetched_at: '2026-09-25T03:20:00+08:00' }], degraded_to: 'rule' },
    { dimension: 'fix', value: { upgrade: { target_version: '0.6.2', advisory_url: `https://github.com/vllm-project/vllm/security/advisories` }, mitigation: '升级至 v0.6.2 以上版本；临时方案：在 API 网关层过滤危险参数' }, confidence: 0.88, source: ['github', 'nvd'], evidence: [{ source: 'github', url: 'https://github.com/vllm-project/vllm/releases/tag/v0.6.2', snippet: 'v0.6.2 安全修复版本发布，修复了 API 注入导致的 RCE 问题。', fetched_at: '2026-09-25T03:20:00+08:00' }] },
    { dimension: 'consistency', value: { consensus: 'all_sources_agree', conflicts: [], timeline: [{ event: 'published', at: v.published_at }, { event: 'poc_released', at: '2026-09-23T00:00:00+08:00' }, { event: 'patched', at: '2026-09-24T00:00:00+08:00' }] }, confidence: 0.85, source: ['nvd', 'github', 'arxiv'], evidence: [{ source: 'nvd', url: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`, snippet: '多源信息一致，无冲突。', fetched_at: '2026-09-25T03:20:00+08:00' }] },
  ]
  for (const d of dims) {
    enrichments.push({ dimension: d.dimension, value: d.value, source: d.source, evidence: d.evidence, confidence: d.confidence, mock: true, model: 'deepseek-v4-flash', agent: 'EnrichAgent', version: 2, degraded_to: (d as any).degraded_to ?? null, degraded_reason: '', quality_score: d.dimension === 'consistency' ? 0.83 : undefined, created_at: '2026-09-25T03:21:00+08:00' })
  }
  return {
    enrichments,
    graph: {
      nodes: [
        { id: v.id, type: 'Vuln', label: v.cve_id },
        { id: 'p_vllm', type: 'Product', label: 'vLLM' },
        { id: 'p_paper', type: 'Paper', label: 'arXiv:2510.01234' },
        { id: 't_t1059', type: 'Technique', label: 'T1059.009' },
      ],
      edges: [
        { src: v.id, rel: 'AFFECTS', dst: 'p_vllm', type: 'Product' },
        { src: v.id, rel: 'MENTIONED_IN', dst: 'p_paper', type: 'Paper' },
        { src: v.id, rel: 'MAPS_TO', dst: 't_t1059', type: 'Technique' },
      ],
    },
  }
}

// ── 本地资产扫描（A 线）demo 数据 ──
// 口径：静态演示专用样本，标注 demo，不代表任何真实扫描结果。

export const mockAssetsAlerts: AssetAlert[] = [
  {
    alert_id: 'al_demo_001',
    created_at: '2026-10-08T21:14:00+08:00',
    name: 'vllm',
    version: '0.6.1',
    repo_path: 'D:\\AgentPrograms\\demo-inference',
    cve_id: 'CVE-2026-12345',
    intel_id: 'intel_demo_vllm',
    severity: 'critical',
    title: 'vLLM 远程代码执行漏洞（API 注入）',
    matched_rule: '< 0.6.2',
    matched_ranges: ['< 0.6.2'],
    reason: '组件版本满足受影响版本规则（厂商身份未经本地核实）',
    vendor_unverified: true,
    status: 'new',
  },
  {
    alert_id: 'al_demo_002',
    created_at: '2026-10-08T21:14:00+08:00',
    name: 'langchain',
    version: '0.1.9',
    repo_path: 'D:\\AgentPrograms\\demo-agent',
    cve_id: 'CVE-2026-12344',
    intel_id: 'intel_demo_langchain',
    severity: 'high',
    title: 'LangChain SSRF 漏洞（工具链注入）',
    matched_rule: '< 0.2.0',
    matched_ranges: ['< 0.2.0'],
    reason: '组件版本满足受影响版本规则（厂商身份未经本地核实）',
    vendor_unverified: true,
    status: 'seen',
  },
]

export const mockAssetsOverview: AssetsOverview = {
  scope: 'assets',
  data_mode: 'fixture',
  last_run: {
    run_id: 'run_demo',
    finished_at: '2026-10-08T21:13:40+08:00',
    repo_count: 3,
    component_count: 12,
    status: 'ok',
    degraded_to: null,
    note: null,
    roots: ['D:\\AgentPrograms'],
  },
  repo_count: 3,
  component_count: 12,
  alert_count: 2,
  unread_count: 1,
  by_ecosystem: { npm: 8, pypi: 3, docker: 1 },
  alerts: mockAssetsAlerts.filter((a) => a.status === 'new'),
}

export const mockAssetsRepos: { run_id: string | null; repos: AssetRepo[] } = {
  run_id: 'run_demo',
  repos: [
    {
      repo_id: 'repo_demo_1',
      path: 'D:\\AgentPrograms\\demo-agent',
      remote_url: 'https://github.com/demo/agent.git',
      branch: 'main',
      head_commit: '9f2c1ab',
      head_commit_at: '2026-10-07T10:00:00+08:00',
      is_git: true,
      git_note: null,
      languages: ['Python'],
      frameworks: ['LangChain', 'FastAPI'],
      manifests: ['requirements.txt', 'Dockerfile'],
      component_count: 6,
    },
    {
      repo_id: 'repo_demo_2',
      path: 'D:\\AgentPrograms\\demo-inference',
      remote_url: null,
      branch: 'main',
      head_commit: '31aa77c',
      head_commit_at: '2026-10-06T15:30:00+08:00',
      is_git: true,
      git_note: '未配置 origin 远程',
      languages: ['Python', 'Docker'],
      frameworks: ['PyTorch'],
      manifests: ['requirements.txt'],
      component_count: 4,
    },
    {
      repo_id: 'repo_demo_3',
      path: 'D:\\AgentPrograms\\demo-web',
      remote_url: 'https://github.com/demo/web.git',
      branch: 'dev',
      head_commit: null,
      head_commit_at: null,
      is_git: false,
      git_note: null,
      languages: ['Node.js'],
      frameworks: ['Vue', 'Vite'],
      manifests: ['package.json'],
      component_count: 2,
    },
  ],
}

export const mockAssetsComponents: { total: number; rows: AssetComponent[] } = {
  total: 12,
  rows: [
    { ecosystem: 'pypi', name: 'langchain', version: '0.1.9', constraint_raw: '>=0.1.9', version_is_range_floor: true, source_file: 'requirements.txt', repo_path: 'D:\\AgentPrograms\\demo-agent' },
    { ecosystem: 'pypi', name: 'fastapi', version: '0.110.0', constraint_raw: '==0.110.0', version_is_range_floor: false, source_file: 'requirements.txt', repo_path: 'D:\\AgentPrograms\\demo-agent' },
    { ecosystem: 'pypi', name: 'vllm', version: '0.6.1', constraint_raw: '==0.6.1', version_is_range_floor: false, source_file: 'requirements.txt', repo_path: 'D:\\AgentPrograms\\demo-inference' },
    { ecosystem: 'pypi', name: 'torch', version: '', constraint_raw: '*', version_is_range_floor: true, source_file: 'requirements.txt', repo_path: 'D:\\AgentPrograms\\demo-inference' },
    { ecosystem: 'npm', name: 'vue', version: '3.5.13', constraint_raw: '^3.5.0', version_is_range_floor: true, source_file: 'package.json', repo_path: 'D:\\AgentPrograms\\demo-web' },
    { ecosystem: 'npm', name: 'vite', version: '6.0.5', constraint_raw: '^6.0.0', version_is_range_floor: true, source_file: 'package.json', repo_path: 'D:\\AgentPrograms\\demo-web' },
    { ecosystem: 'docker', name: 'nginx', version: '1.25', constraint_raw: '1.25', version_is_range_floor: false, source_file: 'Dockerfile', repo_path: 'D:\\AgentPrograms\\demo-agent' },
  ],
}

export const mockAssetsScanResult: AssetsScanResult = {
  scope: 'assets',
  run_id: 'run_demo',
  status: 'ok',
  degraded_to: null,
  note: null,
  repo_count: 3,
  component_count: 12,
  skipped: 0,
  affected: 2,
  new_alerts: 1,
}

export const mockQaResponse = {
  answer: `根据知识库检索结果，最近影响 vLLM 的高危漏洞主要有以下几条：

1. CVE-2026-12345 — vLLM 远程代码执行漏洞（CVSS 9.8，Critical）
   攻击者通过构造特定的 API 请求，可在 vLLM 推理服务器上执行任意代码。影响所有未打补丁的 vLLM < 0.6.2 实例。已有公开 PoC [1]。

2. CVE-2026-12342 — Ollama 模型加载路径穿越（CVSS 7.5，High）
   通过构造模型文件路径，攻击者可读取 Ollama 服务器上任意文件，可能导致敏感配置泄露 [2]。

建议立即升级 vLLM 至 0.6.2 以上版本，并在 API 网关层对请求参数做严格过滤。`,
  citations: [
    { id: 'S1', title: 'CVE-2026-12345 详情 — NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345', score: 0.92 },
    { id: 'S2', title: 'vLLM Security Advisory — GitHub', url: 'https://github.com/vllm-project/vllm/security/advisories', score: 0.87 },
    { id: 'S3', title: 'Adversarial Attacks on LLM Serving Frameworks — arXiv:2510.01234', url: 'https://arxiv.org/abs/2510.01234', score: 0.81 },
    { id: 'S4', title: 'PoC: vLLM API Injection — GitHub', url: 'https://github.com/poc-corp/cve-2026-12345', score: 0.79 },
  ],
  cost_cny: 0.031,
  degraded: false,
}
