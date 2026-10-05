<script setup lang="ts">
import { onMounted, ref, watch, nextTick } from 'vue'
import { RouterLink } from 'vue-router'
// 按需引入 echarts：本页只用到柱状图/折线图 + 直角坐标系 + 提示框 + 图例。
// 原来 `import * as echarts from 'echarts'` 会把整个库打进主包（实测 1.18 MB / gzip 399 KB），
// 对这种只画两张图的页面是纯浪费；按需引入后主包显著变小。
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([BarChart, LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

import { getJson, BACKEND_DATA_MODE } from '../api'
import StatCards from '../components/StatCards.vue'
import type { CollectStatus, MetricsOverview, Paged, VulnItem } from '../types'

const metrics = ref<MetricsOverview | null>(null)
const status = ref<CollectStatus | null>(null)
const latest = ref<Paged<VulnItem> | null>(null)
const error = ref('')
const loading = ref(true)

const sevChart = ref<HTMLElement | null>(null)
const trendChart = ref<HTMLElement | null>(null)
let sevChartInst: echarts.ECharts | null = null
let trendChartInst: echarts.ECharts | null = null

const trendRange = ref<'7d' | '30d' | '90d' | '1y'>('7d')

type RangeData = { labels: string[]; vulns: number[]; enrich: number[] }

function genTrendData(range: string, items: VulnItem[]): RangeData {
  const dates = items.map((item) => item.published_at ? new Date(item.published_at) : null)
    .filter((date): date is Date => date !== null && Number.isFinite(date.getTime()))
  const anchor = dates.length ? new Date(Math.max(...dates.map((date) => date.getTime()))) : new Date()
  const monthly = range === '1y'
  const stepDays = range === '90d' ? 7 : 1
  const periods = monthly ? 12 : range === '90d' ? 13 : range === '30d' ? 30 : 7
  const labels: string[] = []
  const vulns = Array<number>(periods).fill(0)
  const enrich = Array<number>(periods).fill(0)
  const start = new Date(anchor)
  if (monthly) start.setMonth(start.getMonth() - periods + 1, 1)
  else start.setDate(start.getDate() - (periods - 1) * stepDays)
  for (let index = 0; index < periods; index++) {
    const bucket = new Date(start)
    if (monthly) bucket.setMonth(bucket.getMonth() + index)
    else bucket.setDate(bucket.getDate() + index * stepDays)
    labels.push(monthly
      ? bucket.toLocaleDateString('zh-CN', { year: '2-digit', month: 'numeric' })
      : (bucket.getMonth() + 1) + '/' + bucket.getDate())
  }
  for (const item of items) {
    if (!item.published_at) continue
    const date = new Date(item.published_at)
    if (!Number.isFinite(date.getTime())) continue
    const index = monthly
      ? (date.getFullYear() - start.getFullYear()) * 12 + date.getMonth() - start.getMonth()
      : Math.floor((date.getTime() - start.getTime()) / (stepDays * 86_400_000))
    if (index >= 0 && index < periods) {
      vulns[index] = (vulns[index] ?? 0) + 1
      if (item.enriched) enrich[index] = (enrich[index] ?? 0) + 1
    }
  }
  return { labels, vulns, enrich }
}

function fmtLatency(s: number | null): string {
  if (s === null) return '—'
  if (s < 3600) return `${Math.round(s)}s`
  return `${(s / 3600).toFixed(1)}h`
}

function initSevChart() {
  if (!sevChart.value || !metrics.value) return
  if (sevChartInst) sevChartInst.dispose()
  sevChartInst = echarts.init(sevChart.value)
  const dims = metrics.value.enrich.per_dimension ?? {}
  const names = Object.keys(dims)
  const coverage = names.map(n => ((dims[n]?.coverage_ratio ?? 0) * 100).toFixed(0))
  const confidence = names.map(n => dims[n]?.confidence_avg == null ? null : Number((dims[n].confidence_avg * 100).toFixed(0)))
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

function initTrendChart() {
  if (!trendChart.value) return
  if (trendChartInst) trendChartInst.dispose()
  trendChartInst = echarts.init(trendChart.value)
  const data = genTrendData(trendRange.value, latest.value?.items ?? [])
  const isLongRange = trendRange.value === '90d' || trendRange.value === '1y'
  trendChartInst.setOption({
    tooltip: { trigger: 'axis', backgroundColor: '#0a0f1a', borderColor: '#1e2d44', textStyle: { color: '#e2e8f0' } },
    legend: { data: ['新增漏洞', '富化完成'], textStyle: { color: '#64748b' }, top: 0 },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category', data: data.labels, boundaryGap: false,
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b', fontSize: isLongRange ? 10 : 11, interval: isLongRange ? 'auto' : 0 },
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#1e2d44' } },
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#1e2d44' } },
    },
    series: [
      {
        name: '新增漏洞', type: 'line', smooth: !isLongRange, showSymbol: !isLongRange,
        data: data.vulns,
        lineStyle: { width: 2, color: '#38bdf8' },
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(56, 189, 248, 0.25)' },
          { offset: 1, color: 'rgba(56, 189, 248, 0)' },
        ]) },
        itemStyle: { color: '#38bdf8' },
      },
      {
        name: '富化完成', type: 'line', smooth: !isLongRange, showSymbol: !isLongRange,
        data: data.enrich,
        lineStyle: { width: 2, color: '#818cf8' },
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(129, 140, 248, 0.25)' },
          { offset: 1, color: 'rgba(129, 140, 248, 0)' },
        ]) },
        itemStyle: { color: '#818cf8' },
      },
    ],
  })
}

function switchTrendRange(range: '7d' | '30d' | '90d' | '1y') {
  trendRange.value = range
  initTrendChart()
}

function resizeCharts() {
  sevChartInst?.resize()
  trendChartInst?.resize()
}

onMounted(async () => {
  try {
    const [m, s, l] = await Promise.all([
      getJson<MetricsOverview>('/metrics/overview'),
      getJson<CollectStatus>('/collect/status'),
      getJson<Paged<VulnItem>>('/vulns', { page_size: 100, sort: 'published_at' }),
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
    initTrendChart()
    window.addEventListener('resize', resizeCharts)
  }
})

watch(metrics, () => { nextTick(() => initSevChart()) })
</script>

<template>
  <div v-if="loading" class="muted" style="padding: 40px; text-align: center">
    <span class="spinner" style="margin-right: 8px"></span>
    加载中…
  </div>

  <p v-else-if="error" class="muted">加载失败：{{ error }}</p>

  <template v-else>
    <h1 class="page-title">态势大屏</h1>
    <p class="page-subtitle" v-if="BACKEND_DATA_MODE === 'live'">正式库只读快照：富化只计有当前来源与事件证明的工件；旧记录未核验不算成功。趋势按页面样本的发布时间聚合，不代表实时监测 SLA。</p>
    <p class="page-subtitle" v-else>本机离线 fixture 执行结果：情报数、富化结果与来源记录；非实时漏洞监控。</p>

    <StatCards
      :items="[
        { label: '漏洞总数', value: metrics?.collect.vulns ?? null, icon: 'shield', variant: 'critical' },
        { label: '原始条目', value: metrics?.collect.raw_items ?? null, hint: `去重合并率 ${((metrics?.collect.merge_ratio ?? 0) * 100).toFixed(1)}%`, icon: 'docs' },
        { label: '富化覆盖率', value: metrics ? `${((metrics.enrich.coverage_ratio ?? 0) * 100).toFixed(1)}%` : null, icon: 'spark', variant: 'ok' },
        { label: '采集延迟 P50', value: fmtLatency(metrics?.latency.p50_seconds ?? null), icon: 'clock' },
        { label: '6h 内入库占比', value: metrics?.latency.sla_6h_ratio != null ? `${(metrics.latency.sla_6h_ratio * 100).toFixed(1)}%` : null, icon: 'zap', variant: 'ok' },
        { label: '知识库切片', value: metrics?.knowledge.chunks ?? null, icon: 'box' },
        { label: '模型调用费用', value: '—', hint: 'StepFun 费用暂未计量', icon: 'yen' },
        { label: '在跑任务', value: status?.queue_depth ?? null, icon: 'refresh' },
      ]"
    />

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px">
      <div class="panel fade-in">
        <div class="panel-header">
          <h3>富化维度覆盖与置信度</h3>
          <span class="badge-count">{{ metrics?.enrich.dimensions ?? 7 }} 维度</span>
        </div>
        <div ref="sevChart" style="height: 260px"></div>
      </div>
      <div class="panel fade-in">
        <div class="panel-header">
          <h3>采集趋势</h3>
          <div class="range-selector">
            <button :class="{ active: trendRange === '7d' }" @click="switchTrendRange('7d')">7天</button>
            <button :class="{ active: trendRange === '30d' }" @click="switchTrendRange('30d')">30天</button>
            <button :class="{ active: trendRange === '90d' }" @click="switchTrendRange('90d')">90天</button>
            <button :class="{ active: trendRange === '1y' }" @click="switchTrendRange('1y')">全年</button>
          </div>
        </div>
        <div ref="trendChart" style="height: 260px"></div>
      </div>
    </div>

    <div class="panel fade-in">
      <div class="panel-header">
        <h3>采集源水位线</h3>
        <span class="badge-count">{{ status?.watermarks?.filter(w => w.success).length ?? 0 }}/{{ status?.watermarks?.length ?? 0 }} {{ status?.data_mode === 'fixture' ? '回放成功' : '正常' }}</span>
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
                {{ w.success ? (status?.data_mode === 'fixture' ? '回放成功' : '正常') : w.error ?? '失败' }}
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
