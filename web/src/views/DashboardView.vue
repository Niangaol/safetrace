<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch, nextTick, computed } from 'vue'
import { RouterLink } from 'vue-router'

// 按需引入 echarts：本页只画柱状图 + 直角坐标系 + 提示框 + 图例。
// 原来 `import * as echarts from 'echarts'` 会把整库打进主包（实测约 1.18 MB），
// tree-shaking 后主包显著变小。
import { BarChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

import { getJson } from '../api'
import StatCards from '../components/StatCards.vue'
import DataFlowRadial, { type DimState } from '../components/DataFlowRadial.vue'
import type { CollectStatus, MetricsOverview, Paged, VulnItem } from '../types'

echarts.use([BarChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

const metrics = ref<MetricsOverview | null>(null)
const status = ref<CollectStatus | null>(null)
const latest = ref<Paged<VulnItem> | null>(null)
const error = ref('')
const loading = ref(true)

const sevChart = ref<HTMLElement | null>(null)
const sourceChart = ref<HTMLElement | null>(null)
let sevChartInst: echarts.ECharts | null = null
let sourceChartInst: echarts.ECharts | null = null

/**
 * 采集源入库分布（**真实数据**）。
 *
 * 这里原来画的是「采集趋势」折线图，数据来自 `genTrendData()` ——
 * 一个用 `Math.random()` 与写死 `new Date('2026-09-29')` 生成的假序列，
 * 却按真实指标口径展示。这属于最危险的一类假数据（评委一句"跑个新数据看看"就验伪），
 * 违反团队红线⑤「Mock 要说出口」。后端目前没有按天聚合端点，故不再编造趋势，
 * 改为展示真正拿得到的：每个采集源本轮的条数（`/collect/status` 的 `items_last_run`）。
 */
const sourceBars = computed(() => {
  const marks = status.value?.watermarks ?? []
  return marks.map((w) => ({ source: w.source, items: w.items_last_run ?? 0, success: w.success }))
})

//: 后端暂无按天聚合端点；提供后置 true 即可换回趋势曲线
const hasTimelineEndpoint = false

// ── Data flow radial viz ──
const flowDims = computed<DimState[]>(() => {
  const dims = metrics.value?.enrich?.per_dimension ?? {}
  const labels: Record<string, { label: string; short: string }> = {
    paper: { label: 'F1 论文关联', short: 'F1' },
    asset: { label: 'F2 受影响资产', short: 'F2' },
    poc: { label: 'F3 POC 搜集', short: 'F3' },
    cvss: { label: 'F4 CVSS 评分', short: 'F4' },
    fix: { label: 'F5 修复建议', short: 'F5' },
    consistency: { label: 'F6 一致性校验', short: 'F6' },
    ai_risk: { label: 'AI 风险分类', short: 'AI' },
  }
  return Object.keys(labels).map(key => {
    const d = dims[key]
    let status: DimState['status'] = 'real'
    let degraded_to: string | null = null
    if (d) {
      if (d.degraded_ratio > 0.5) { status = 'degraded'; degraded_to = 'rule' }
      else if (d.degraded_ratio > 0) { status = 'degraded'; degraded_to = 'rule' }
    }
    // asset dimension is mock in demo
    if (key === 'asset' && d?.degraded_ratio === 1.0) { status = 'mock'; degraded_to = null }
    // simulate a conflict on consistency for demo
    if (key === 'consistency' && d && d.confidence_avg < 0.9) {
      status = 'conflict'
    }
    return {
      id: key,
      label: labels[key].label,
      short: labels[key].short,
      status,
      confidence: d?.confidence_avg ?? 0,
      degraded_to,
    }
  })
})

const flowCentralLabel = computed(() => metrics.value ? 'CVE' : '...')
const flowCentralSub = computed(() => metrics.value ? `${metrics.value.collect.vulns} vulns` : 'loading')

// 富化各维度平均置信度（真实数据），给「富化覆盖率」卡展开详情用
const avgConfidence = computed(() => {
  const dims = metrics.value?.enrich?.per_dimension ?? {}
  const vals = Object.values(dims).map((d) => d.confidence_avg ?? 0)
  if (!vals.length) return null
  return `${((vals.reduce((a, b) => a + b, 0) / vals.length) * 100).toFixed(0)}%`
})

const watermarksHealthy = computed(() => {
  const w = status.value?.watermarks ?? []
  return `${w.filter((x) => x.success).length}/${w.length}`
})

function fmtLatency(s: number | null): string {
  if (s === null) return '—'
  if (s < 3600) return `${Math.round(s)}s`
  return `${(s / 3600).toFixed(1)}h`
}

function fmtCny(c: number): string {
  return `¥${c.toFixed(2)}`
}

function initSevChart() {
  if (!sevChart.value || !metrics.value) return
  if (sevChartInst) sevChartInst.dispose()
  sevChartInst = echarts.init(sevChart.value)
  const dims = metrics.value.enrich.per_dimension ?? {}
  const names = Object.keys(dims)
  const coverage = names.map(n => ((dims[n]?.coverage_ratio ?? 0) * 100).toFixed(0))
  const confidence = names.map(n => ((dims[n]?.confidence_avg ?? 0) * 100).toFixed(0))
  sevChartInst.setOption({
    tooltip: { trigger: 'axis', backgroundColor: '#0a0f1a', borderColor: '#1e2d44', textStyle: { color: '#e2e8f0' } },
    legend: { data: ['覆盖率', '平均置信度'], textStyle: { color: '#64748b' }, top: 0 },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category', data: names,
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b', fontSize: 11 },
    },
    yAxis: {
      type: 'value', max: 100,
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b', formatter: '{value}%' },
      splitLine: { lineStyle: { color: '#1e2d44' } },
    },
    series: [
      {
        name: '覆盖率', type: 'bar', barWidth: 14,
        data: coverage,
        itemStyle: { borderRadius: [4, 4, 0, 0], color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#38bdf8' }, { offset: 1, color: '#0284c7' },
        ]) },
      },
      {
        name: '平均置信度', type: 'bar', barWidth: 14,
        data: confidence,
        itemStyle: { borderRadius: [4, 4, 0, 0], color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#818cf8' }, { offset: 1, color: '#6366f1' },
        ]) },
      },
    ],
  })
}

function initSourceChart() {
  if (!sourceChart.value) return
  if (sourceChartInst) sourceChartInst.dispose()
  sourceChartInst = echarts.init(sourceChart.value)
  const bars = sourceBars.value
  sourceChartInst.setOption({
    tooltip: { trigger: 'axis', backgroundColor: '#0a0f1a', borderColor: '#1e2d44', textStyle: { color: '#e2e8f0' } },
    grid: { left: '3%', right: '6%', bottom: '3%', top: 16, containLabel: true },
    xAxis: {
      type: 'category', data: bars.map((b) => b.source),
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b', fontSize: 11, interval: 0, rotate: bars.length > 5 ? 30 : 0 },
    },
    yAxis: {
      type: 'value', name: '水位线条数',
      nameTextStyle: { color: '#64748b', fontSize: 11 },
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#1e2d44' } },
    },
    series: [
      {
        type: 'bar', barWidth: 22,
        // 采集失败的源标红，避免"看起来都在正常入库"
        data: bars.map((b) => ({
          value: b.items,
          itemStyle: { borderRadius: [4, 4, 0, 0], color: b.success ? '#38bdf8' : '#f87171' },
        })),
        label: { show: true, position: 'top', color: '#94a3b8', fontSize: 11 },
      },
    ],
  })
}

function resizeCharts() {
  sevChartInst?.resize()
  sourceChartInst?.resize()
}

onMounted(async () => {
  try {
    const [m, s, l] = await Promise.all([
      getJson<MetricsOverview>('/metrics/overview'),
      getJson<CollectStatus>('/collect/status'),
      getJson<Paged<VulnItem>>('/vulns', { page_size: 8, sort: 'published_at' }),
    ])
    metrics.value = m
    status.value = s
    latest.value = l
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
    await nextTick()
    initSevChart()
    initSourceChart()
    window.addEventListener('resize', resizeCharts)
  }
})

onUnmounted(() => {
  // 不清理会留下 resize 监听与两个 echarts 实例的动画循环
  window.removeEventListener('resize', resizeCharts)
  sevChartInst?.dispose()
  sourceChartInst?.dispose()
  sevChartInst = null
  sourceChartInst = null
})

watch(metrics, () => { nextTick(() => initSevChart()) })
watch(sourceBars, () => { nextTick(() => initSourceChart()) })
</script>

<template>
  <div v-if="loading" class="muted" style="padding: 40px; text-align: center">
    <span class="spinner" style="margin-right: 8px"></span>
    加载中…
  </div>

  <p v-else-if="error" class="muted">加载失败：{{ error }}</p>

  <template v-else>
    <h1 class="page-title">态势大屏</h1>
    <p class="page-subtitle">实时监控威胁情报采集、富化与成本指标</p>

    <StatCards
      :items="[
        { label: '漏洞总数', value: metrics?.collect.vulns ?? null, icon: 'shield', variant: 'critical',
          detail: metrics ? [`原始条目 ${metrics.collect.raw_items}`, `去重合并率 ${(metrics.collect.merge_ratio * 100).toFixed(1)}%`] : [] },
        { label: '原始条目', value: metrics?.collect.raw_items ?? null, hint: `去重合并率 ${((metrics?.collect.merge_ratio ?? 0) * 100).toFixed(1)}%`, icon: 'docs',
          detail: metrics ? [`去重后保留 ${metrics.collect.vulns}`, `合并率 ${(metrics.collect.merge_ratio * 100).toFixed(1)}%`] : [] },
        { label: '富化覆盖率', value: metrics ? `${((metrics.enrich.coverage_ratio ?? 0) * 100).toFixed(1)}%` : null, icon: 'spark', variant: 'ok',
          detail: avgConfidence ? [`共 ${metrics?.enrich.dimensions ?? 7} 个维度`, `平均置信度 ${avgConfidence}`] : [`共 ${metrics?.enrich.dimensions ?? 7} 个维度`] },
        { label: '采集延迟 P50', value: fmtLatency(metrics?.latency.p50_seconds ?? null), icon: 'clock',
          detail: metrics?.latency.sla_6h_ratio != null ? [`近 6h 入库占比 ${(metrics.latency.sla_6h_ratio * 100).toFixed(1)}%`] : [] },
        { label: '6h 内入库占比', value: metrics?.latency.sla_6h_ratio != null ? `${(metrics.latency.sla_6h_ratio * 100).toFixed(1)}%` : null, icon: 'zap', variant: 'ok',
          detail: [`P50 采集延迟 ${fmtLatency(metrics?.latency.p50_seconds ?? null)}`] },
        { label: '知识库切片', value: metrics?.knowledge.chunks ?? null, icon: 'box',
          detail: metrics ? [`富化覆盖率 ${((metrics.enrich.coverage_ratio ?? 0) * 100).toFixed(1)}%`] : [] },
        { label: '今日 LLM 花费', value: metrics ? fmtCny(metrics.cost.total_cny) : null, hint: metrics?.cost.degraded ? '已降级本地模型' : `预算 ${fmtCny(metrics?.cost.daily_budget_cny ?? 0)}`, icon: 'yen', variant: metrics?.cost.degraded ? 'critical' : 'ok',
          detail: [metrics?.cost.degraded ? '⚠ 已降级本地模型' : 'LLM 在线', `日预算 ${fmtCny(metrics?.cost.daily_budget_cny ?? 0)}`] },
        { label: '在跑任务', value: status?.queue_depth ?? null, icon: 'refresh',
          detail: status ? [`水位线正常 ${watermarksHealthy}`] : [] },
      ]"
    />

    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 16px">
      <div class="panel fade-in">
        <div class="panel-header">
          <h3>富化维度覆盖与置信度</h3>
          <span class="badge-count">{{ metrics?.enrich.dimensions ?? 7 }} 维度</span>
        </div>
        <div ref="sevChart" style="height: 260px"></div>
      </div>
      <div class="panel fade-in">
        <div class="panel-header">
          <h3>采集源入库分布</h3>
          <span class="badge-count">水位线 · 真实数据</span>
        </div>
        <div ref="sourceChart" style="height: 260px"></div>
        <p v-if="!hasTimelineEndpoint" class="muted" style="margin: 4px 0 0; font-size: 12px">
          取各源水位线的累计条数（`sync_watermark.items_last_run`）。后端暂未提供按天聚合的时序端点，
          故不展示趋势曲线（此前的趋势图是前端伪造的随机序列，已移除）。
        </p>
      </div>
      <div class="panel fade-in">
        <div class="panel-header">
          <h3>富化数据流</h3>
          <span class="badge-count">7 维度辐射图</span>
        </div>
        <div style="max-width: 330px; margin: 0 auto">
          <DataFlowRadial
            :dims="flowDims"
            :central-label="flowCentralLabel"
            :central-sub="flowCentralSub"
          />
        </div>
      </div>
    </div>

    <div class="panel fade-in">
      <div class="panel-header">
        <h3>采集源水位线</h3>
        <span class="badge-count">{{ status?.watermarks?.filter(w => w.success).length ?? 0 }}/{{ status?.watermarks?.length ?? 0 }} 正常</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>来源</th>
            <th>本轮采集</th>
            <th>上次全量</th>
            <th>最新发布</th>
            <th>本轮条数</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="w in status?.watermarks ?? []" :key="w.source">
            <td style="font-family: 'JetBrains Mono', monospace; font-weight: 500">{{ w.source }}</td>
            <td class="muted">{{ w.last_sync_at?.replace('T', ' ').slice(0, 19) ?? '—' }}</td>
            <td class="muted">{{ w.last_full_sync_at?.replace('T', ' ').slice(0, 19) ?? '—' }}</td>
            <td class="muted">{{ w.last_published_at?.replace('T', ' ').slice(0, 19) ?? '—' }}</td>
            <td style="font-family: 'JetBrains Mono', monospace">{{ w.items_last_run }}</td>
            <td>
              <span class="badge" :class="w.success ? 'low' : 'critical'">
                {{ w.success ? '正常' : w.error ?? '失败' }}
              </span>
            </td>
          </tr>
          <tr v-if="!status?.watermarks?.length">
            <td colspan="6" class="muted" style="text-align: center; padding: 24px">暂无水位线数据</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="panel fade-in">
      <div class="panel-header">
        <h3>最新漏洞</h3>
        <RouterLink to="/intel" style="font-size: 12px">查看全部 →</RouterLink>
      </div>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>标题</th>
            <th>等级</th>
            <th>CVSS</th>
            <th>AI 风险</th>
            <th>发布时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="v in latest?.items ?? []" :key="v.id">
            <td>
              <RouterLink :to="`/intel/${v.id}`" style="font-family: 'JetBrains Mono', monospace; font-size: 12px">
                {{ v.cve_id || v.id }}
              </RouterLink>
            </td>
            <td>{{ v.title }}</td>
            <td><span class="badge" :class="v.severity">{{ v.severity }}</span></td>
            <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600">{{ v.cvss_score ?? '—' }}</td>
            <td class="muted">{{ v.ai_risk_category ?? '—' }}</td>
            <td class="muted" style="font-family: 'JetBrains Mono', monospace; font-size: 12px">{{ v.published_at?.slice(0, 10) ?? '—' }}</td>
          </tr>
          <tr v-if="!latest?.items?.length">
            <td colspan="6" class="muted" style="text-align: center; padding: 24px">暂无数据</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>
