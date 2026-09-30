<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import { getJson } from '../api'
import SystemFactory from '../components/SystemFactory.vue'
import TerminalWindow from '../components/TerminalWindow.vue'
import ThreatGlobe from '../components/ThreatGlobe.vue'
import type { CollectStatus, MetricsOverview } from '../types'

const router = useRouter()

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
    { value: m ? String(m.collect.vulns) : '—', label: '漏洞情报', icon: 'shield' },
    { value: m ? String(m.collect.raw_items) : '—', label: '原始条目', icon: 'docs' },
    { value: sources != null ? String(sources) : '—', label: '采集来源', icon: 'globe' },
    { value: m ? `${((m.enrich.coverage_ratio ?? 0) * 100).toFixed(0)}%` : '—', label: '富化覆盖', icon: 'spark' },
  ]
})

/** 终端日志里的数字同样来自真实接口；null 一律显示「未运行」，不编造 */
function fmt(n: number | null | undefined): string {
  return n == null ? '未运行' : n.toLocaleString()
}
function ratio(r: number | null | undefined): string {
  return r == null ? '未运行' : `${(r * 100).toFixed(0)}%`
}

const STAT_ICONS: Record<string, string> = {
  shield: 'M12 2L2 7v10l10 5 10-5V7L12 2z M12 22V12 M2 7l10 5 10-5',
  docs: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8',
  globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M2 12h20 M12 2a15.3 15.3 0 0 1 0 20 15.3 15.3 0 0 1 0-20z',
  spark: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z',
}



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
      <div class="hero-bg">
        <div class="hero-grid"></div>
        <div class="orb orb-a"></div>
        <div class="orb orb-b"></div>
        <div class="orb orb-c"></div>
        <div class="globe-viewport" @click="router.push('/dashboard')">
          <ThreatGlobe @enter="router.push('/dashboard')" />
        </div>
      </div>
      <div class="hero-content">
        <div class="hero-badge">
          <span class="hero-badge-dot"></span>
          AI Security Intelligence
        </div>
        <h1 class="hero-title">
          <!-- 两层叠放实现光扫：base 参与排版，glow 绝对定位覆盖，保证标题真正水平居中 -->
          <span class="ht-stack">
            <span class="ht-base">SafeTrace</span>
            <span class="ht-glow" aria-hidden="true">SafeTrace</span>
          </span>
        </h1>
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
      <div
        v-for="s in stats"
        :key="s.label"
        class="stat-item"
        title="点击进入态势大屏"
        @click="router.push('/dashboard')"
      >
        <div class="stat-icon">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path :d="STAT_ICONS[s.icon]" />
          </svg>
        </div>
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
      <div class="section-kicker">Pipeline</div>
      <h2 class="section-title">系统运转 · 数据流转</h2>
      <div class="factory-panel fade-in" title="点击进入态势大屏" @click="router.push('/dashboard')">
        <span class="panel-go">点击进入大屏 →</span>
        <SystemFactory
          :raw-items="metrics?.collect.raw_items ?? null"
          :vulns="metrics?.collect.vulns ?? null"
          :merge-ratio="metrics?.collect.merge_ratio ?? null"
          :coverage-ratio="metrics?.enrich.coverage_ratio ?? null"
          :chunks="metrics?.knowledge.chunks ?? null"
          :per-dimension="metrics?.enrich.per_dimension ?? null"
        />
        <TerminalWindow
          class="factory-term"
          title="safe_trace@pipeline: ./run --watch"
          :status="`▮ 数字可点击跳转到对应页面 · ⤢ 放大 / Esc 还原`"
        >
          <div class="term-line">
            <span class="term-prompt">root@safetrace</span><span class="term-dim">:</span><span class="term-path">~/pipeline</span><span class="term-dim">$</span>
            <span class="term-cmd">./run --collect --enrich --alert</span>
          </div>
          <div class="term-line">
            <span class="term-ok">▮</span> 采集线 Y · 原始条目
            <RouterLink class="term-link" to="/dashboard">{{ fmt(metrics?.collect.raw_items) }}</RouterLink>
            → 漏洞
            <RouterLink class="term-link" to="/intel">{{ fmt(metrics?.collect.vulns) }}</RouterLink>
            <span class="term-dim">（去重合并 {{ ratio(metrics?.collect.merge_ratio) }}）</span>
          </div>
          <div class="term-line">
            <span class="term-ok">▮</span> 富化线 F · 七维覆盖率
            <RouterLink class="term-link" to="/dashboard">{{ ratio(metrics?.enrich.coverage_ratio) }}</RouterLink>
            <span class="term-dim">· {{ fmt(metrics?.enrich.records) }} 条已富化</span>
          </div>
          <div class="term-line">
            <span class="term-ok">▮</span> 底座线 S · 知识库分块
            <RouterLink class="term-link" to="/qa">{{ fmt(metrics?.knowledge.chunks) }}</RouterLink>
            <span class="term-dim">（pgvector · RRF 检索）</span>
          </div>
          <div class="term-line">
            <span class="term-ok">▮</span> 问答线 Q · 智能体运行
            <RouterLink class="term-link" to="/qa">{{ fmt(metrics?.agents.runs) }}</RouterLink> 次
            <span class="term-dim">（失败 {{ fmt(metrics?.agents.failed) }}，未运行则显示「未运行」）</span>
          </div>
        </TerminalWindow>
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
      <div class="section-kicker">Agents &amp; Tools</div>
      <h2 class="section-title">智能体与工具</h2>
      <p class="section-subtitle">
        运行数字来自 <code>/agents/runs</code> · 无记录如实显示「未运行」
      </p>
      <div class="agents-grid">
        <div
          v-for="a in agents"
          :key="a.graph"
          class="agent-card"
          title="点击进入态势大屏"
          @click="router.push('/dashboard')"
        >
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
  /* 下方 340px 是完整的北半球穹顶带（canvas 320px）+ 一点呼吸余量 */
  padding: 96px 24px 344px;
  border-radius: 16px;
  overflow: hidden;
  margin-bottom: 0;
  isolation: isolate;
}
.hero-bg {
  position: absolute;
  inset: 0;
  z-index: -1;
  background:
    radial-gradient(ellipse 62% 80% at 50% 0%, rgba(56, 189, 248, 0.14), transparent 70%),
    radial-gradient(ellipse 42% 62% at 24% 100%, rgba(129, 140, 248, 0.09), transparent 70%),
    radial-gradient(ellipse 42% 62% at 76% 100%, rgba(167, 139, 250, 0.07), transparent 70%);
}
.hero-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(56, 189, 248, 0.055) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56, 189, 248, 0.055) 1px, transparent 1px);
  background-size: 46px 46px;
  -webkit-mask-image: radial-gradient(ellipse 65% 70% at 50% 42%, #000 25%, transparent 72%);
  mask-image: radial-gradient(ellipse 65% 70% at 50% 42%, #000 25%, transparent 72%);
}
.orb {
  position: absolute;
  border-radius: 50%;
}
/* 光晕：静态径向渐变。
   原来三颗 460/620/800px 的 orb 都在跑 scale 动画 —— 每帧缩放会重新光栅化
   整块大面积渐变，是首页 CPU 占用的大头。这里改为静态渐变，视觉几乎无差别。 */
.orb-a {
  width: 460px; height: 460px;
  top: -90px; left: 50%;
  transform: translateX(-50%);
  background: radial-gradient(circle, rgba(56, 189, 248, 0.16), transparent 68%);
}
.orb-b {
  width: 620px; height: 620px;
  top: -160px; left: 50%;
  transform: translateX(-50%);
  background: radial-gradient(circle, rgba(129, 140, 248, 0.1), transparent 68%);
}
.orb-c {
  width: 800px; height: 800px;
  top: -260px; left: 50%;
  transform: translateX(-50%);
  background: radial-gradient(circle, rgba(167, 139, 250, 0.07), transparent 68%);
}
/* 上半球穹顶：ThreatGlobe canvas 区域，完整画出一个北半球，不做容器裁切 */
.globe-viewport {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  z-index: 0;
  height: 320px;
  pointer-events: none;
}
.globe-viewport > * {
  pointer-events: auto;
}
.hero-content {
  position: relative;
  z-index: 1;
  /* 显式居中：badge / 标题 / 副标题 / 按钮全部以中轴对齐 */
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}
.hero-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: #7dd3fc;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.24);
  border-radius: 20px;
  padding: 5px 16px;
  margin-bottom: 24px;
}
.hero-badge-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: #22c55e;
  box-shadow: 0 0 8px rgba(34, 197, 94, 0.8);
  animation: badgePulse 2.4s ease-in-out infinite;
}
@keyframes badgePulse {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(0.6); opacity: 0.6; }
}
.hero-title {
  font-size: 82px;
  font-weight: 800;
  letter-spacing: -0.02em;
  line-height: 1.1;
  margin: 0 0 10px;
}
/* 标题叠层：父级 block + text-align:center 居中；glow 层绝对定位覆盖在 base 上 */
.ht-stack {
  position: relative;
  display: inline-block;
}
.ht-base {
  position: relative;
  z-index: 1;
  font: inherit;
  background: linear-gradient(
    178deg,
    #ffffff 0%,
    #e8eef7 18%,
    #9cc8f2 42%,
    #64b5f6 62%,
    #1e88e5 82%,
    #1565c0 100%
  );
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
  /* 静态光晕：一次性绘制，不参与光扫动画重绘，避免滤镜拖慢动画 */
  text-shadow: 0 0 40px rgba(56, 189, 248, 0.35), 0 0 90px rgba(56, 189, 248, 0.2);
}
/* 真实光扫：一道亮带单独扫过文字表面（文字其余部分保持稳态金属渐变） */
.ht-glow {
  position: absolute;
  left: 0;
  top: 0;
  font: inherit;
  background: linear-gradient(
    102deg,
    transparent 18%,
    rgba(255, 255, 255, 0.5) 40%,
    rgba(255, 255, 255, 0.95) 50%,
    rgba(255, 255, 255, 0.5) 60%,
    transparent 82%
  );
  background-size: 240px 100%;
  background-repeat: no-repeat;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
  pointer-events: none;
  /* 扫光周期拉到 9s：观感不变，但每秒重绘帧数少一半 */
  animation: htSweep 9s ease-in-out infinite;
}
@keyframes htSweep {
  0%, 12% { background-position: -260px 0; }
  55% { background-position: 620px 0; }
  100% { background-position: 1020px 0; }
}
.hero-subtitle {
  font-size: 21px;
  color: #e2e8f0;
  margin: 0 0 6px;
  font-weight: 500;
  letter-spacing: 1px;
}
.hero-desc {
  font-size: 13px;
  color: #64748b;
  margin: 0 0 34px;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.5px;
}
.hero-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
}
.hero-btn {
  display: inline-block;
  padding: 13px 30px;
  border-radius: 9px;
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.22s;
}
.hero-btn.primary {
  background: linear-gradient(135deg, #38bdf8, #0284c7);
  color: #06121f;
  box-shadow: 0 0 24px rgba(56, 189, 248, 0.35);
  position: relative;
  overflow: hidden;
}
.hero-btn.primary:hover {
  transform: translateY(-2px) scale(1.03);
  box-shadow: 0 0 34px rgba(56, 189, 248, 0.55);
}
.hero-btn.primary::after {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 40%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.35), transparent);
  transform: skewX(-20deg) translateX(-180%);
  animation: btnSweep 3.4s ease-in-out infinite;
}
@keyframes btnSweep {
  0%, 55% { transform: skewX(-20deg) translateX(-180%); }
  100% { transform: skewX(-20deg) translateX(360%); }
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
  position: relative;
  padding-top: 26px;
  cursor: pointer;
  transition: transform 0.2s;
}
.stat-item:hover {
  transform: translateY(-3px);
}
.stat-icon {
  position: absolute;
  top: 0;
  left: 50%;
  transform: translateX(-50%);
  color: #38bdf8;
  display: flex;
  align-items: center;
  filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.6));
}
.stat-value {
  display: block;
  font-size: 36px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  color: #f1f5f9;
  transition: color 0.2s;
}
.stat-item:hover .stat-value {
  color: #7dd3fc;
  text-shadow: 0 0 18px rgba(56, 189, 248, 0.45);
}
.stat-label {
  display: block;
  font-size: 12px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 6px;
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
.feature-card::after {
  content: '';
  position: absolute;
  top: 0; left: -80%;
  width: 55%; height: 100%;
  background: linear-gradient(100deg, transparent, rgba(148, 197, 255, 0.09), transparent);
  transform: skewX(-20deg);
  transition: left 0.55s ease;
}
.feature-card:hover {
  border-color: rgba(56, 189, 248, 0.5);
  transform: translateY(-4px) scale(1.02);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3), 0 0 24px rgba(56,189,248,0.14);
}
.feature-card:hover::before { opacity: 1; }
.feature-card:hover::after { left: 140%; }
.feature-icon {
  width: 52px; height: 52px;
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(56, 189, 248, 0.16), rgba(129, 140, 248, 0.12));
  border: 1px solid rgba(56, 189, 248, 0.25);
  color: #7dd3fc;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 18px;
  filter: drop-shadow(0 0 10px rgba(56, 189, 248, 0.25));
  transition: all 0.25s;
}
.feature-card:hover .feature-icon {
  background: linear-gradient(135deg, #38bdf8, #0284c7);
  color: #06121f;
  filter: drop-shadow(0 0 14px rgba(56, 189, 248, 0.6));
  transform: scale(1.06);
}
.feature-title {
  font-size: 17px;
  font-weight: 600;
  color: #f1f5f9;
  margin: 0 0 6px;
  transition: color 0.2s;
}
.feature-card:hover .feature-title {
  color: #7dd3fc;
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
.section-kicker {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: #38bdf8;
  text-align: center;
  margin: 0 0 10px;
}
.section-title {
  font-size: 24px;
  font-weight: 700;
  color: #f1f5f9;
  text-align: center;
  margin: 0 0 20px;
  letter-spacing: 0.5px;
  position: relative;
  display: inline-block;
  left: 50%;
  transform: translateX(-50%);
}
.section-title::after {
  content: '';
  position: absolute;
  left: 50%;
  bottom: -10px;
  transform: translateX(-50%);
  width: 46px; height: 3px;
  border-radius: 3px;
  background: linear-gradient(90deg, transparent, #38bdf8, transparent);
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
  position: relative;
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 14px;
  padding: 28px 24px 20px;
  overflow: hidden;
  cursor: pointer;
  transition: border-color 0.25s, box-shadow 0.25s;
}
.factory-panel:hover {
  border-color: rgba(56, 189, 248, 0.45);
  box-shadow: 0 10px 34px rgba(56, 189, 248, 0.1);
}
.panel-go {
  position: absolute;
  top: 14px;
  right: 18px;
  font-size: 11px;
  letter-spacing: 1px;
  color: #38bdf8;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.25);
  border-radius: 12px;
  padding: 3px 12px;
  z-index: 2;
  opacity: 0.75;
  transition: opacity 0.2s;
}
.factory-panel:hover .panel-go {
  opacity: 1;
}
/* 终端日志：贴在数据流转图下方，读数与图一一对应 */
.factory-term {
  margin-top: 20px;
  cursor: default;
}
.factory-term :deep(.tw-body) {
  max-height: 220px;
}
.term-line {
  padding: 4px 10px;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 11.5px;
  line-height: 1.55;
  color: #9cc8f2;
  border-bottom: 1px dashed rgba(42, 64, 96, 0.3);
}
.term-line:last-child { border-bottom: none; }
.term-line b { color: #e2e8f0; font-weight: 600; }
/* 终端里的数字可点击追溯到对应页面 */
.term-link {
  color: #7dd3fc;
  text-decoration: none;
  border-bottom: 1px dashed rgba(125, 211, 252, 0.5);
  padding: 0 1px;
}
.term-link:hover {
  color: #bae6fd;
  border-bottom-color: #bae6fd;
  background: rgba(56, 189, 248, 0.1);
}
.term-prompt { color: #34d399; }
.term-path { color: #7dd3fc; }
.term-cmd { color: #e2e8f0; }
.term-ok { color: #34d399; }
.term-dim { color: #5b6b85; }
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
  gap: 20px;
  margin-bottom: 40px;
}
.agent-card {
  display: flex;
  align-items: center;
  gap: 14px;
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 14px;
  padding: 26px 24px;
  cursor: pointer;
  transition: border-color 0.2s, transform 0.2s, box-shadow 0.2s;
}
.agent-card:hover {
  border-color: rgba(56, 189, 248, 0.45);
  transform: translateY(-3px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3), 0 0 20px rgba(56, 189, 248, 0.1);
}
.agent-dot {
  width: 14px; height: 14px;
  border-radius: 50%;
  flex-shrink: 0;
  animation: agentPulse 2s infinite;
}
@keyframes agentPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.agent-info { display: flex; flex-direction: column; gap: 4px; }
.agent-metrics {
  font-size: 12px;
  color: #64748b;
  font-family: 'JetBrains Mono', monospace;
}
.agent-state {
  margin-left: auto;
  font-size: 12px;
  padding: 5px 12px;
  border-radius: 8px;
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
  padding: 14px 16px;
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
  font-size: 16px;
  font-weight: 600;
  color: #e2e8f0;
  font-family: 'JetBrains Mono', monospace;
}
.agent-role {
  font-size: 13px;
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
