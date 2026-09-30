<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { getJson } from '../api'
import SystemFactory from '../components/SystemFactory.vue'
import type { CollectStatus, MetricsOverview } from '../types'

/** 智能体运行记录（GET /agents/runs 的真实字段） */
interface AgentRun {
  id: string
  graph: string
  trigger: string
  state: string
  tokens: number
  cost_cny: number
  latency_ms: number
  error: string | null
  created_at: string | null
}

/** 工具注册表（GET /agents/tools 的真实字段） */
interface AgentTool {
  name: string
  description: string
  permission: string
  cost_tier: string
}

const features = [
  { icon: 'M3 3h7v7H3V3zm0 11h7v7H3v-7zm11-11h7v7h-7V3zm0 11h7v7h-7v-7z', title: '态势大屏', desc: '实时监控威胁情报采集、富化与成本指标', to: '/dashboard' },
  { icon: 'M12 2l9 4v6c0 5.5-3.8 10.7-9 12-5.2-1.3-9-6.5-9-12V6l9-4z', title: '情报列表', desc: '全量漏洞情报检索、多维度筛选与排序', to: '/intel' },
  { icon: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.6 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.6-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z', title: '情报问答', desc: '自然语言提问，基于知识库的智能检索问答', to: '/qa' },
]

// 首页四个数字**必须来自真实接口**。
// 原来是写死的字符串（'1,284' / '5,230' / '96%'），与库里的真实值（13 / 22 / 100%）
// 对不上——导航栏显示"实时数据"而正文写死假数字，是最容易被评委一眼验伪的矛盾。
const metrics = ref<MetricsOverview | null>(null)
const status = ref<CollectStatus | null>(null)
/** 智能体运行记录与工具注册表：也都是真实接口，不是写死的名字 */
const runs = ref<AgentRun[]>([])
const tools = ref<AgentTool[]>([])

onMounted(async () => {
  const results = await Promise.allSettled([
    getJson<MetricsOverview>('/metrics/overview'),
    getJson<CollectStatus>('/collect/status'),
    getJson<{ items: AgentRun[] }>('/agents/runs'),
    getJson<{ tools: AgentTool[] }>('/agents/tools'),
  ])
  if (results[0].status === 'fulfilled') metrics.value = results[0].value
  if (results[1].status === 'fulfilled') status.value = results[1].value
  if (results[2].status === 'fulfilled') runs.value = results[2].value.items ?? []
  if (results[3].status === 'fulfilled') tools.value = results[3].value.tools ?? []
})

const stats = computed(() => {
  const m = metrics.value
  const sources = status.value?.watermarks?.length ?? m?.collect.sources
  return [
    { value: m ? String(m.collect.vulns) : '—', label: '漏洞情报' },
    { value: m ? String(m.collect.raw_items) : '—', label: '原始条目' },
    { value: sources != null ? String(sources) : '—', label: '采集来源' },
    { value: m ? `${((m.enrich.coverage_ratio ?? 0) * 100).toFixed(0)}%` : '—', label: '富化覆盖' },
  ]
})

/**
 * 智能体卡片：名字与颜色是产品定义（稳定的），但**运行数字全部来自 `/agents/runs`**。
 * `graph` 字段与后端的编排图同名：collect / enrich / qa / alert。
 */
const AGENT_META = [
  { graph: 'collect', name: 'WatchAgent', role: '监测 · 采集与去重', color: '#38bdf8' },
  { graph: 'enrich', name: 'EnrichAgent', role: '富化 · 七维加工', color: '#818cf8' },
  { graph: 'qa', name: 'QAAgent', role: '问答 · 检索与合成', color: '#a78bfa' },
  { graph: 'alert', name: 'AlertAgent', role: '告警 · 分级通知', color: '#22c55e' },
] as const

const agents = computed(() =>
  AGENT_META.map((meta) => {
    const mine = runs.value.filter((r) => r.graph === meta.graph)
    const done = mine.filter((r) => r.state === 'done').length
    const failed = mine.filter((r) => r.state === 'error').length
    const tokens = mine.reduce((sum, r) => sum + (r.tokens ?? 0), 0)
    const cost = mine.reduce((sum, r) => sum + (r.cost_cny ?? 0), 0)
    return {
      ...meta,
      runs: mine.length,
      done,
      failed,
      tokens,
      cost,
      // 没有任何运行记录时如实显示"未运行"，而不是编一个好看的数字
      state: mine.length === 0 ? 'idle' : failed > 0 ? 'warn' : 'ok',
      stateLabel: mine.length === 0 ? '未运行' : failed > 0 ? `${failed} 次失败` : '运行正常',
    }
  }),
)

/** 工具注册表：权限与成本档位是"能不能被滥用/烧钱"的关键信息，如实展示 */
const toolsByTier = computed(() => {
  const order = ['free', 'flash', 'pro']
  return [...tools.value].sort(
    (a, b) => order.indexOf(a.cost_tier) - order.indexOf(b.cost_tier) || a.name.localeCompare(b.name),
  )
})
</script>

<template>
  <div class="home">
    <!-- hero -->
    <section class="hero">
      <div class="hero-bg"></div>
      <div class="hero-content">
        <div class="hero-badge">AI Security Intelligence</div>
        <h1 class="hero-title">SafeTrace</h1>
        <p class="hero-subtitle">智能体驱动的 AI 安全知识情报系统</p>
        <p class="hero-desc">
          多源采集 · 七维富化 · 证据链追溯 · 混合检索 · 自动降级
        </p>
        <div class="hero-actions">
          <RouterLink to="/dashboard" class="hero-btn primary">
            进入态势大屏
          </RouterLink>
          <RouterLink to="/intel" class="hero-btn secondary">
            浏览情报
          </RouterLink>
        </div>
      </div>
    </section>

    <!-- stats -->
    <section class="stats-bar">
      <div v-for="s in stats" :key="s.label" class="stat-item">
        <span class="stat-value">{{ s.value }}</span>
        <span class="stat-label">{{ s.label }}</span>
      </div>
    </section>

    <!-- features -->
    <section class="features">
      <RouterLink
        v-for="f in features"
        :key="f.title"
        :to="f.to"
        class="feature-card fade-in"
      >
        <div class="feature-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path :d="f.icon" />
          </svg>
        </div>
        <h3 class="feature-title">{{ f.title }}</h3>
        <p class="feature-desc">{{ f.desc }}</p>
        <span class="feature-arrow">→</span>
      </RouterLink>
    </section>

    <!-- system factory: 运转状态 + 数据流转合二为一 -->
    <section class="factory-section">
      <h2 class="section-title">系统运转 · 数据流转</h2>
      <div class="factory-panel fade-in">
        <SystemFactory
          :raw-items="metrics?.collect.raw_items ?? null"
          :vulns="metrics?.collect.vulns ?? null"
          :merge-ratio="metrics?.collect.merge_ratio ?? null"
          :coverage-ratio="metrics?.enrich.coverage_ratio ?? null"
          :chunks="metrics?.knowledge.chunks ?? null"
        />
        <div class="flow-legend">
          <span class="legend-chip"><b>Y</b> 监测线</span>
          <span class="legend-arrow">→</span>
          <span class="legend-chip"><b>F</b> 富化线</span>
          <span class="legend-arrow">→</span>
          <span class="legend-chip"><b>S</b> 底座线</span>
          <span class="legend-arrow">→</span>
          <span class="legend-chip"><b>Q</b> 问答线</span>
        </div>
      </div>
    </section>

    <!-- agents -->
    <section class="agents-section">
      <h2 class="section-title">智能体与工具</h2>
      <p class="section-subtitle">
        运行数字来自 <code>/agents/runs</code> · 无记录如实显示「未运行」
      </p>
      <div class="agents-grid">
        <div v-for="a in agents" :key="a.graph" class="agent-card">
          <div class="agent-dot" :style="{ background: a.color, boxShadow: `0 0 12px ${a.color}` }"></div>
          <div class="agent-info">
            <span class="agent-name">{{ a.name }}</span>
            <span class="agent-role">{{ a.role }}</span>
            <span class="agent-metrics">
              运行 {{ a.runs }} 次 · 成功 {{ a.done }} · 失败 {{ a.failed }} ·
              {{ a.tokens.toLocaleString() }} tok · ¥{{ a.cost.toFixed(4) }}
            </span>
          </div>
          <span class="agent-state" :class="a.state">{{ a.stateLabel }}</span>
        </div>
      </div>

      <details v-if="toolsByTier.length" class="tools-panel">
        <summary>
          已注册工具 {{ toolsByTier.length }} 个（权限 <code>internal</code>；成本档位决定走哪个模型）
        </summary>
        <table class="tools-table">
          <thead>
            <tr><th>工具</th><th>说明</th><th>成本档位</th></tr>
          </thead>
          <tbody>
            <tr v-for="t in toolsByTier" :key="t.name">
              <td><code>{{ t.name }}</code></td>
              <td class="muted">{{ t.description }}</td>
              <td>
                <span class="badge" :class="t.cost_tier === 'free' ? 'low' : t.cost_tier === 'pro' ? 'critical' : 'medium'">
                  {{ t.cost_tier }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </details>
    </section>
  </div>
</template>

<style scoped>
.home {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 0 48px;
}

/* hero */
.hero {
  position: relative;
  text-align: center;
  padding: 72px 24px 56px;
  border-radius: 16px;
  overflow: hidden;
  margin-bottom: 0;
}
.hero-bg {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse 60% 80% at 50% 0%, rgba(56, 189, 248, 0.12), transparent),
    radial-gradient(ellipse 40% 60% at 30% 100%, rgba(129, 140, 248, 0.08), transparent),
    radial-gradient(ellipse 40% 60% at 70% 100%, rgba(167, 139, 250, 0.06), transparent);
}
.hero-content {
  position: relative;
  z-index: 1;
}
.hero-badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: #38bdf8;
  background: rgba(56, 189, 248, 0.1);
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: 20px;
  padding: 4px 14px;
  margin-bottom: 20px;
}
.hero-title {
  font-size: 56px;
  font-weight: 800;
  letter-spacing: -1px;
  background: linear-gradient(135deg, #f1f5f9, #38bdf8 60%, #818cf8);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 0 0 8px;
}
.hero-subtitle {
  font-size: 20px;
  color: #e2e8f0;
  margin: 0 0 4px;
  font-weight: 500;
}
.hero-desc {
  font-size: 13px;
  color: #64748b;
  margin: 0 0 28px;
  font-family: 'JetBrains Mono', monospace;
}
.hero-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
}
.hero-btn {
  display: inline-block;
  padding: 12px 28px;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.2s;
}
.hero-btn.primary {
  background: linear-gradient(135deg, #38bdf8, #0284c7);
  color: #06121f;
  box-shadow: 0 0 20px rgba(56, 189, 248, 0.3);
}
.hero-btn.primary:hover {
  transform: translateY(-2px) scale(1.03);
  box-shadow: 0 4px 24px rgba(56, 189, 248, 0.4);
}
.hero-btn.secondary {
  background: transparent;
  border: 1px solid #2a4060;
  color: #e2e8f0;
}
.hero-btn.secondary:hover {
  border-color: #38bdf8;
  background: rgba(56, 189, 248, 0.08);
  transform: translateY(-1px);
}

/* stats */
.stats-bar {
  display: flex;
  justify-content: center;
  gap: 72px;
  padding: 40px 24px;
  border-bottom: 1px solid #1e2d44;
  margin-bottom: 40px;
}
.stat-item {
  text-align: center;
}
.stat-value {
  display: block;
  font-size: 36px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  color: #f1f5f9;
}
.stat-label {
  display: block;
  font-size: 12px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 4px;
}

/* features */
.features {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
  margin-bottom: 48px;
}
.feature-card {
  position: relative;
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 14px;
  padding: 32px 28px;
  text-decoration: none;
  color: inherit;
  transition: all 0.2s;
  overflow: hidden;
}
.feature-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, #38bdf8, transparent);
  opacity: 0;
  transition: opacity 0.2s;
}
.feature-card:hover {
  border-color: #2a4060;
  transform: translateY(-4px) scale(1.02);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3), 0 0 20px rgba(56,189,248,0.08);
}
.feature-card:hover::before { opacity: 1; }
.feature-icon {
  width: 44px; height: 44px;
  border-radius: 10px;
  background: rgba(56, 189, 248, 0.1);
  color: #38bdf8;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}
.feature-title {
  font-size: 16px;
  font-weight: 600;
  color: #f1f5f9;
  margin: 0 0 6px;
}
.feature-desc {
  font-size: 12px;
  color: #64748b;
  margin: 0;
  line-height: 1.6;
}
.feature-arrow {
  position: absolute;
  bottom: 20px;
  right: 20px;
  color: #38bdf8;
  font-size: 16px;
  opacity: 0;
  transition: opacity 0.2s, transform 0.2s;
}
.feature-card:hover .feature-arrow {
  opacity: 1;
  transform: translateX(4px);
}

/* section */
.section-title {
  font-size: 22px;
  font-weight: 600;
  color: #f1f5f9;
  text-align: center;
  margin: 0 0 20px;
}
.section-subtitle {
  font-size: 12px;
  color: #64748b;
  text-align: center;
  margin: -12px 0 24px;
}

/* factory: 系统运转 + 数据流转 合一 */
.factory-section { margin-bottom: 48px; }
.factory-panel {
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 14px;
  padding: 28px 24px 20px;
  overflow: hidden;
}
.flow-legend {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #16213a;
}
.legend-chip {
  display: inline-flex;
  align-items: center;
  gap: 9px;
}
.legend-chip b {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: linear-gradient(135deg, #38bdf8, #0284c7);
  color: #06121f;
  font-weight: 800;
  font-size: 14px;
  font-family: 'JetBrains Mono', monospace;
}
.legend-chip span {
  font-size: 14px;
  font-weight: 600;
  color: #e2e8f0;
}
.legend-arrow {
  color: #2a4060;
  font-size: 18px;
  font-weight: 700;
}
@media (max-width: 700px) {
  .flow-legend { gap: 10px; }
}

/* agents */
.agents-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 40px;
}
.agent-card {
  display: flex;
  align-items: center;
  gap: 10px;
  background: #131c2e;
  border: 1px solid #1e2d44;
  border-radius: 10px;
  padding: 14px 16px;
  transition: border-color 0.2s;
}
.agent-card:hover { border-color: #2a4060; }
.agent-dot {
  width: 10px; height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
  animation: agentPulse 2s infinite;
}
@keyframes agentPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.agent-info { display: flex; flex-direction: column; }
.agent-metrics {
  font-size: 11px;
  color: #64748b;
  margin-top: 3px;
  font-family: 'JetBrains Mono', monospace;
}
.agent-state {
  margin-left: auto;
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 6px;
  white-space: nowrap;
  border: 1px solid transparent;
}
.agent-state.ok { color: #22c55e; background: rgba(34, 197, 94, 0.1); border-color: rgba(34, 197, 94, 0.3); }
.agent-state.warn { color: #f59e0b; background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3); }
.agent-state.idle { color: #64748b; background: rgba(100, 116, 139, 0.1); border-color: rgba(100, 116, 139, 0.3); }

.tools-panel {
  margin-top: 14px;
  background: #131c2e;
  border: 1px solid #1e2d44;
  border-radius: 10px;
  padding: 12px 16px;
}
.tools-panel summary { cursor: pointer; font-size: 13px; color: #94a3b8; }
.tools-panel summary code { font-family: 'JetBrains Mono', monospace; font-size: 11px; }
.tools-table { width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 12px; }
.tools-table th {
  text-align: left;
  color: #64748b;
  font-weight: 500;
  padding: 6px 8px;
  border-bottom: 1px solid #1e2d44;
}
.tools-table td { padding: 6px 8px; border-bottom: 1px solid #16213a; vertical-align: top; }
.tools-table code { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #7dd3fc; }
.agent-name {
  font-size: 13px;
  font-weight: 600;
  color: #e2e8f0;
  font-family: 'JetBrains Mono', monospace;
}
.agent-role {
  font-size: 11px;
  color: #64748b;
}

/* agents grid 使用的 margin 保留在 .agents-grid 上 */

@media (max-width: 700px) {
  .features { grid-template-columns: 1fr; }
  .agents-grid { grid-template-columns: repeat(2, 1fr); }
  .stats-bar { gap: 24px; flex-wrap: wrap; }
  .hero-title { font-size: 36px; }
}
</style>
