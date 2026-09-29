<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { getJson } from '../api'
import SystemFactory from '../components/SystemFactory.vue'
import type { CollectStatus, MetricsOverview } from '../types'

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

onMounted(async () => {
  try {
    const [m, s] = await Promise.all([
      getJson<MetricsOverview>('/metrics/overview'),
      getJson<CollectStatus>('/collect/status'),
    ])
    metrics.value = m
    status.value = s
  } catch {
    // 取不到就显示占位符，而不是编一个好看的假数字
  }
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

const agents = [
  { name: 'TriageAgent', role: '分流与路由', color: '#38bdf8' },
  { name: 'EnrichAgent', role: '七维富化', color: '#818cf8' },
  { name: 'QAAgent', role: '检索问答', color: '#a78bfa' },
  { name: 'WatchAgent', role: '监控告警', color: '#22c55e' },
]
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

    <!-- system factory animation -->
    <section class="factory-section">
      <h2 class="section-title">系统运转</h2>
      <p class="section-subtitle">五条流水线循环运行 · 采集 → 分流 → 富化 → 底座 → 问答</p>
      <div class="factory-panel fade-in">
        <SystemFactory />
      </div>
    </section>

    <!-- agents -->
    <section class="agents-section">
      <h2 class="section-title">智能体架构</h2>
      <p class="section-subtitle">四条并行线协同工作，LangGraph 状态机编排</p>
      <div class="agents-grid">
        <div v-for="a in agents" :key="a.name" class="agent-card">
          <div class="agent-dot" :style="{ background: a.color, boxShadow: `0 0 12px ${a.color}` }"></div>
          <div class="agent-info">
            <span class="agent-name">{{ a.name }}</span>
            <span class="agent-role">{{ a.role }}</span>
          </div>
        </div>
      </div>
    </section>

    <!-- pipeline -->
    <section class="pipeline-section">
      <h2 class="section-title">数据流转</h2>
      <div class="pipeline-flow">
        <div class="pipe-step">
          <span class="pipe-num">Y</span>
          <span class="pipe-label">监测线</span>
          <span class="pipe-desc">采集 · 去重 · 派发</span>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-step">
          <span class="pipe-num">F</span>
          <span class="pipe-label">富化线</span>
          <span class="pipe-desc">论文 · 资产 · POC · CVSS · 修复 · 一致性 · AI风险</span>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-step">
          <span class="pipe-num">S</span>
          <span class="pipe-label">底座线</span>
          <span class="pipe-desc">知识库 · 总线 · 索引 · 工具</span>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-step">
          <span class="pipe-num">Q</span>
          <span class="pipe-label">问答线</span>
          <span class="pipe-desc">意图 · 检索 · 推理 · 合成</span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.home {
  max-width: 960px;
  margin: 0 auto;
  padding: 0 0 40px;
}

/* hero */
.hero {
  position: relative;
  text-align: center;
  padding: 60px 24px 48px;
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
  font-size: 48px;
  font-weight: 800;
  letter-spacing: -1px;
  background: linear-gradient(135deg, #f1f5f9, #38bdf8 60%, #818cf8);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 0 0 8px;
}
.hero-subtitle {
  font-size: 18px;
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
  gap: 48px;
  padding: 32px 24px;
  border-bottom: 1px solid #1e2d44;
  margin-bottom: 32px;
}
.stat-item {
  text-align: center;
}
.stat-value {
  display: block;
  font-size: 28px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  color: #f1f5f9;
}
.stat-label {
  display: block;
  font-size: 11px;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 4px;
}

/* features */
.features {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 40px;
}
.feature-card {
  position: relative;
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 12px;
  padding: 28px 24px;
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
  font-size: 20px;
  font-weight: 600;
  color: #f1f5f9;
  text-align: center;
  margin: 0 0 4px;
}
.section-subtitle {
  font-size: 12px;
  color: #64748b;
  text-align: center;
  margin: 0 0 24px;
}

/* factory */
.factory-section { margin-bottom: 40px; }
.factory-panel {
  background: linear-gradient(135deg, #131c2e, #0f1623);
  border: 1px solid #1e2d44;
  border-radius: 12px;
  padding: 20px;
  overflow: hidden;
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

/* pipeline */
.pipeline-section { margin-bottom: 20px; }
.pipeline-flow {
  display: flex;
  align-items: stretch;
  gap: 0;
  flex-wrap: wrap;
  justify-content: center;
}
.pipe-step {
  flex: 1;
  min-width: 140px;
  background: #131c2e;
  border: 1px solid #1e2d44;
  border-radius: 10px;
  padding: 16px 14px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}
.pipe-num {
  width: 32px; height: 32px;
  border-radius: 50%;
  background: linear-gradient(135deg, #38bdf8, #0284c7);
  color: #06121f;
  font-weight: 800;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 4px;
}
.pipe-label {
  font-size: 13px;
  font-weight: 600;
  color: #e2e8f0;
}
.pipe-desc {
  font-size: 10px;
  color: #64748b;
  text-align: center;
}
.pipe-arrow {
  display: flex;
  align-items: center;
  color: #2a4060;
  font-size: 20px;
  padding: 0 8px;
}

@media (max-width: 700px) {
  .features { grid-template-columns: 1fr; }
  .agents-grid { grid-template-columns: repeat(2, 1fr); }
  .stats-bar { gap: 24px; flex-wrap: wrap; }
  .hero-title { font-size: 36px; }
}
</style>
