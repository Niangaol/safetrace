<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { getJson } from '../api'
import type { EvidenceResponse, VulnItem } from '../types'

const props = defineProps<{ id: string }>()

const vuln = ref<VulnItem | null>(null)
const chain = ref<EvidenceResponse | null>(null)
const openDims = ref<Set<string>>(new Set())
const error = ref('')
const loading = ref(true)

const DIM_LABEL: Record<string, string> = {
  paper: '论文支撑', asset: '受影响资产', poc: 'POC 复现',
  cvss: 'CVSS 与影响', fix: '修复建议', consistency: '一致性校验',
  ai_risk: 'AI 风险分类', attack: '攻击技战术',
  impact: '影响评估', mitre_attack: 'ATT&CK 映射',
  cwe: 'CWE 分类', timeline: '事件脉络',
}

const DIM_ICON: Record<string, string> = {
  paper: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8',
  asset: 'M2 2h20v6H2z M2 16h20v6H2z M6 6h.01 M6 20h.01',
  poc: 'M13 2L3 14h9l-1 8 10-12h-9z',
  cvss: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12z M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  fix: 'M14.7 6.3a1 1 0 0 1 1.4 0l1.6 1.6a1 1 0 0 1 0 1.4L8 19l-3 1 1-3z M12.3 8.7l3 3',
  consistency: 'M12 2L2 7v10l10 5 10-5V7L12 2z M9 12l2 2 4-4',
  ai_risk: 'M12 2L2 7v10l10 5 10-5V7L12 2z M12 22V12',
  attack: 'M12 2L2 7v10l10 5 10-5V7L12 2z M14.5 2.5L21 9 M12 6l6 6',
}

function toggle(dim: string) {
  const next = new Set(openDims.value)
  if (next.has(dim)) next.delete(dim)
  else next.add(dim)
  openDims.value = next
}

function renderValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value !== 'object') return String(value)
  return Object.entries(value as Record<string, unknown>)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : JSON.stringify(v)}`)
    .join(' · ')
}

onMounted(async () => {
  try {
    const [v, e] = await Promise.all([
      getJson<VulnItem>(`/vulns/${props.id}`),
      getJson<EvidenceResponse>(`/vulns/${props.id}/evidence`),
    ])
    vuln.value = v
    chain.value = e
  } catch (err) {
    error.value = (err as Error).message
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div v-if="loading" class="muted" style="padding: 40px; text-align: center">
    <span class="spinner" style="margin-right: 8px"></span>
    加载中…
  </div>

  <p v-else-if="error" class="muted">加载失败：{{ error }}</p>

  <template v-else-if="vuln">
    <div style="margin-bottom: 16px">
      <RouterLink to="/intel" style="font-size: 12px">← 返回列表</RouterLink>
    </div>

    <h1 class="page-title" style="font-size: 20px; margin-bottom: 4px">{{ vuln.title }}</h1>
    <p class="page-subtitle" style="display: flex; gap: 12px; align-items: center; margin-bottom: 20px">
      <span style="font-family: 'JetBrains Mono', monospace">{{ vuln.cve_id || vuln.id }}</span>
      <span v-if="vuln.ghsa_id" class="muted">· {{ vuln.ghsa_id }}</span>
      <span class="muted">· 发布于 {{ vuln.published_at?.slice(0, 19).replace('T', ' ') ?? '—' }}</span>
    </p>

    <div class="cards" style="margin-bottom: 20px">
      <div class="card" :class="vuln.severity === 'critical' ? 'critical' : vuln.severity === 'high' ? 'warn' : 'ok'">
        <div class="label">危险等级</div>
        <div class="value">
          <span class="badge" :class="vuln.severity">{{ vuln.severity }}</span>
        </div>
        <div v-if="vuln.exploit_status" class="hint">利用状态：{{ vuln.exploit_status }}</div>
        <div class="icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px">
            <path :d="DIM_ICON[vuln.severity === 'critical' ? 'attack' : 'cvss']" />
          </svg>
        </div>
      </div>
      <div class="card">
        <div class="label">CVSS 基础分</div>
        <div class="value">{{ vuln.cvss_score ?? '—' }}</div>
        <div class="hint" style="font-family: 'JetBrains Mono', monospace; font-size: 10px">{{ vuln.cvss_vector ?? '无向量' }}</div>
      </div>
      <div class="card">
        <div class="label">AI 风险分类</div>
        <div class="value" style="font-size: 18px">{{ vuln.ai_risk_category ?? '—' }}</div>
      </div>
      <div class="card">
        <div class="label">来源数 / 采集延迟</div>
        <div class="value">{{ vuln.source_count }}</div>
        <div class="hint">{{ vuln.collect_latency_seconds != null ? `${(vuln.collect_latency_seconds / 3600).toFixed(1)}h` : '—' }}</div>
      </div>
    </div>

    <div class="panel fade-in" style="margin-bottom: 16px">
      <div class="panel-header"><h3>描述</h3></div>
      <p class="answer">{{ vuln.description || vuln.summary || '暂无描述' }}</p>
      <div v-if="vuln.cwe.length" class="muted" style="margin-top: 12px; font-size: 12px">
        <strong>CWE：</strong>{{ vuln.cwe.join('、') }}
      </div>
      <div v-if="vuln.cpe.length" class="muted" style="margin-top: 4px; font-size: 12px">
        <strong>CPE：</strong>{{ vuln.cpe.slice(0, 3).join('、') }}
      </div>
    </div>

    <div class="panel fade-in">
      <div class="panel-header">
        <h3>富化证据链</h3>
        <span class="badge-count">{{ chain?.enrichments?.length ?? 0 }} 维度</span>
      </div>
      <p v-if="chain?.data_mode === 'fixture'" class="muted" style="font-size: 12px; margin-top: 0">
        fixture 模式：URL / 时间来自 RawDoc 记录；展示文字是多源归并摘要，不是逐源原文片段。请点击来源链接核对上游内容。
      </p>
      <p v-else class="muted" style="font-size: 12px; margin-top: 0">
        每个字段均显示其来源信息与证据状态。
      </p>

      <div v-for="e in chain?.enrichments ?? []" :key="e.dimension" style="margin-bottom: 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden">
        <div style="display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--bg-elevated); cursor: pointer" @click="toggle(e.dimension)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; color: var(--accent); flex-shrink: 0">
            <path :d="DIM_ICON[e.dimension] || 'M12 2L2 7v10l10 5 10-5V7L12 2z'" />
          </svg>
          <strong style="min-width: 100px">{{ DIM_LABEL[e.dimension] ?? e.dimension }}</strong>
          <span v-if="e.confidence != null" class="badge info">置信度 {{ (e.confidence * 100).toFixed(0) }}%</span>
          <span v-if="e.mock" class="badge warn">预置数据</span>
          <span v-if="e.degraded_to" class="badge warn">降级：{{ e.degraded_to }}</span>
          <span v-if="e.quality_score != null" class="badge info">质量分 {{ (e.quality_score * 100).toFixed(0) }}%</span>
          <span class="muted" style="font-size: 11px; margin-left: auto">{{ e.model }} · v{{ e.version }}</span>
          <button class="secondary" style="padding: 4px 12px; font-size: 12px">
            {{ openDims.has(e.dimension) ? '收起' : `证据（${e.evidence.length}）` }}
          </button>
        </div>
        <div style="padding: 12px 16px; border-top: 1px solid var(--border)">
          <div class="muted" style="font-size: 12px">
            <span v-if="e.source?.length"><strong>来源：</strong>{{ e.source.join(' / ') }} · </span>
            {{ renderValue(e.value) }}
          </div>
          <div v-if="e.degraded_reason" class="label muted" style="margin-top: 4px">
            {{ e.degraded_reason }}
          </div>

          <div v-if="openDims.has(e.dimension)" style="margin-top: 12px">
            <div v-for="(ev, i) in e.evidence" :key="i" class="evidence">
              <a v-if="ev.url" :href="ev.url" target="_blank" rel="noreferrer" style="font-size: 12px">
                {{ ev.source }} · {{ ev.url }}
              </a>
              <span v-else class="muted" style="font-size: 12px">{{ ev.source }}（本地计算，无可点开链接）</span>
              <div class="snippet">{{ ev.snippet }}</div>
              <div class="label muted" style="margin-top: 4px">
                抓取于 {{ ev.fetched_at ?? '—' }}
              </div>
            </div>
            <p v-if="!e.evidence.length" class="muted" style="font-size: 12px">该字段暂无证据，请人工确认。</p>
          </div>
        </div>
      </div>

      <p v-if="!chain?.enrichments?.length" class="muted">
        尚未富化。可调用 POST /enrich/backfill 补齐。
      </p>
    </div>

    <div v-if="chain?.graph.edges.length" class="panel fade-in" style="margin-top: 16px">
      <div class="panel-header"><h3>关系视图</h3></div>
      <table>
        <thead>
          <tr><th>起点</th><th>关系</th><th>终点</th></tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in chain.graph.edges" :key="i">
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 12px">{{ e.src }}</td>
            <td><span class="badge info">{{ e.rel }}</span></td>
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 12px">{{ e.dst }} <span class="muted">({{ e.type }})</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>
