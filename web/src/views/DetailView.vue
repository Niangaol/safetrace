<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { getJson, IS_DEMO_MODE, BACKEND_DATA_MODE } from '../api'
import type { EvidenceResponse, Evidence, Enrichment, VulnItem } from '../types'
import CountUpNumber from '../effects/CountUpNumber.vue'
import RevealOnScroll from '../effects/RevealOnScroll.vue'

const props = defineProps<{ id: string }>()

const vuln = ref<VulnItem | null>(null)
type ProofEvidence = Evidence & { original_sha256?: string; artifact_sha256?: string; text_sha256?: string; parent_lineage_ids?: string[] }
type DetailEvidence = EvidenceResponse & { historical_unknown?: boolean; recorded_result_present?: boolean; dimension_states?: { dimension: string; status: string; reason?: string; has_last_good?: boolean }[] }
const chain = ref<DetailEvidence | null>(null)
const focusDims = ['paper', 'cvss', 'fix', 'asset', 'poc']
function proofLabel(e?: Enrichment): string {
  if (e?.dimension === 'asset' || e?.dimension === 'poc') return '未实现 · 样例不算实证'
  if (IS_DEMO_MODE || chain.value?.data_mode === 'fixture' || e?.mock) return 'fixture / 预置样例'
  if (e?.degraded_to) return '降级 · 待复核'
  if (e?.evidence.length && e.evidence.every(ev => { const p = ev as ProofEvidence; return p.original_sha256 && p.artifact_sha256 && p.text_sha256 && p.parent_lineage_ids?.length })) return '可证明 · 来源与工件已绑定'
  if (chain.value?.historical_unknown || chain.value?.recorded_result_present && !e) return 'historical / 历史未知'
  return 'unknown / 尚无充分证明'
}
const dimensionCards = computed(() => focusDims.map(dimension => {
  const result = chain.value?.enrichments.find(e => e.dimension === dimension)
  const state = chain.value?.dimension_states?.find(s => s.dimension === dimension)
  return { dimension, result, state, status: dimension === 'asset' || dimension === 'poc' ? '未实现' : proofLabel(result) }
}))
function limitation(dim: string): string {
  return ({ paper: '相关研究不等于该漏洞复现；需核对 CVE、产品与论文关联。', cvss: '评分只适用于来源声明的 CVE / 版本；风险评分不是准确率，缺失不按 0 处理。', fix: '只读修复指引；不是已执行或已验证修复，适用版本与来源须人工复核。', asset: '未接入真实资产清单，不推断你的环境已受影响。', poc: '未实现隔离 PoC 自动复现，不将利用链接当复现成功。' } as Record<string, string>)[dim] ?? '结论须按来源范围复核。'
}
function proofHashes(ev: Evidence): string {
  const p = ev as ProofEvidence
  return '原文 SHA-256: ' + (p.original_sha256 ?? '未提供') + '\n工件 SHA-256: ' + (p.artifact_sha256 ?? '未提供') + '\n文本 SHA-256: ' + (p.text_sha256 ?? '未提供') + '\nlineage: ' + (p.parent_lineage_ids?.join(' / ') || '未提供')
}
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
      getJson<DetailEvidence>(`/vulns/${props.id}/evidence`),
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

    <h1 class="page-title fx-underline" style="font-size: 20px; margin-bottom: 4px">{{ vuln.title }}</h1>
    <p class="page-subtitle" style="display: flex; gap: 12px; align-items: center; margin-bottom: 20px">
      <span style="font-family: 'JetBrains Mono', monospace">{{ vuln.cve_id || vuln.id }}</span>
      <span v-if="vuln.ghsa_id" class="muted">· {{ vuln.ghsa_id }}</span>
      <span class="muted">· 发布于 {{ vuln.published_at?.slice(0, 19).replace('T', ' ') ?? '—' }}</span>
    </p>

    <p class="muted detail-note">模块二 · 富化与证据 ｜ {{ IS_DEMO_MODE ? '静态样例' : BACKEND_DATA_MODE === 'live' ? '正式库只读' : BACKEND_DATA_MODE === 'fixture' ? '本地 fixture 样例' : '模式待核验' }}。结果记录不等于全部维度完成；置信分 / 质量分均不是准确率。</p>
    <section class="dimension-grid" aria-label="逐维可信状态">
      <article v-for="(card, index) in dimensionCards" :key="card.dimension" class="dimension-card fx-sheen fx-lift" data-sheen :style="{ '--fx-delay': index * 80 + 'ms' }"><h3>{{ DIM_LABEL[card.dimension] }}</h3><strong>{{ card.status }}</strong><p>来源：{{ card.result?.source?.join(' / ') || card.result?.evidence.map(e => e.source).join(' / ') || '未提供' }}</p><p>范围：当前 {{ vuln.cve_id || vuln.id }}；{{ card.result ? '以该维度字段和引用声明为准' : '暂无可核验结论' }}</p><p>{{ limitation(card.dimension) }}</p><small v-if="card.state">运行状态：{{ card.state.status }} · {{ card.state.reason || '无说明' }}{{ card.state.has_last_good ? ' · 保留 last-good（不等于本轮成功）' : '' }}</small></article>
    </section>
    <div class="cards fx-in" style="margin-bottom: 20px">
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
        <div class="value"><CountUpNumber v-if="vuln.cvss_score != null" :value="vuln.cvss_score" :decimals="1" /><template v-else>—</template></div>
        <div class="hint" style="font-family: 'JetBrains Mono', monospace; font-size: 10px">{{ vuln.cvss_vector ?? '无向量' }}</div>
      </div>
      <div class="card">
        <div class="label">AI 风险分类</div>
        <div class="value" style="font-size: 18px">{{ vuln.ai_risk_category ?? '—' }}</div>
      </div>
      <div class="card">
        <div class="label">来源数 / 采集延迟</div>
        <div class="value"><CountUpNumber :value="vuln.source_count" suffix=" 个" /></div>
        <div class="hint">{{ vuln.collect_latency_seconds != null ? `${(vuln.collect_latency_seconds / 3600).toFixed(1)}h` : '未测' }}</div>
      </div>
    </div>

    <RevealOnScroll as="div" :delay="60">
    <div class="panel fade-in" style="margin-bottom: 16px">
      <div class="panel-header"><h3 class="fx-underline">描述</h3></div>
      <p class="answer">{{ vuln.description || vuln.summary || '暂无描述' }}</p>
      <div v-if="vuln.cwe.length" class="muted" style="margin-top: 12px; font-size: 12px">
        <strong>CWE：</strong>{{ vuln.cwe.join('、') }}
      </div>
      <div v-if="vuln.cpe.length" class="muted" style="margin-top: 4px; font-size: 12px">
        <strong>CPE：</strong>{{ vuln.cpe.slice(0, 3).join('、') }}
      </div>
    </div>

    </RevealOnScroll>

    <RevealOnScroll as="div" :delay="120">
    <div class="panel fade-in">
      <div class="panel-header">
        <h3 class="fx-underline">富化证据链</h3>
        <span class="badge-count">{{ chain?.enrichments?.length ?? 0 }} 维度</span>
      </div>
      <p v-if="chain?.data_mode === 'fixture'" class="muted" style="font-size: 12px; margin-top: 0">
        fixture 模式：URL / 时间来自 RawDoc 记录；展示文字是多源归并摘要，不是逐源原文片段。请点击来源链接核对上游内容。
      </p>
      <p v-else class="muted" style="font-size: 12px; margin-top: 0">
        可证明需来源、工件 hash 与 lineage 绑定；unknown / historical 不算已核验。以下保留接口实际返回字段，不补造来源。
      </p>

      <div v-for="e in chain?.enrichments ?? []" :key="e.dimension" class="fx-sheen" data-sheen style="margin-bottom: 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden">
        <div style="display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--bg-elevated); cursor: pointer" @click="toggle(e.dimension)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; color: var(--accent); flex-shrink: 0">
            <path :d="DIM_ICON[e.dimension] || 'M12 2L2 7v10l10 5 10-5V7L12 2z'" />
          </svg>
          <strong style="min-width: 100px">{{ DIM_LABEL[e.dimension] ?? e.dimension }}</strong>
          <span class="badge warn">{{ proofLabel(e) }}</span>
          <span v-if="e.confidence != null" class="badge info">启发式置信分（非准确率） {{ (e.confidence * 100).toFixed(0) }}%</span>
          <span v-if="e.mock" class="badge warn">预置数据</span>
          <span v-if="e.degraded_to" class="badge warn">降级：{{ e.degraded_to }}</span>
          <span v-if="e.quality_score != null" class="badge info">质量分（非准确率） {{ (e.quality_score * 100).toFixed(0) }}%</span>
          <span class="muted" style="font-size: 11px; margin-left: auto">{{ e.model }} · v{{ e.version }}</span>
          <button class="secondary" style="padding: 4px 12px; font-size: 12px">
            {{ openDims.has(e.dimension) ? '收起' : `证据（${e.evidence.length}）` }}
          </button>
        </div>
        <div style="padding: 12px 16px; border-top: 1px solid var(--border)">
          <div class="muted" style="font-size: 12px">
            <span v-if="e.source?.length"><strong>来源：</strong>{{ e.source.join(' / ') }} · </span>
            <pre class="dimension-value">{{ renderValue(e.value) }}</pre>
            <p>{{ limitation(e.dimension) }}</p>
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
                引用编号 {{ ev.evidence_id ?? '未提供' }} · 抓取于 {{ ev.fetched_at ?? '未提供' }}
                <pre class="hash-proof">{{ proofHashes(ev) }}</pre>
              </div>
            </div>
            <p v-if="!e.evidence.length" class="muted" style="font-size: 12px">该字段暂无证据，请人工确认。</p>
          </div>
        </div>
      </div>

      <p v-if="!chain?.enrichments?.length" class="muted">
        暂无可展示的富化证据。历史记录未核验仍为 unknown；补跑需先备份并显式授权，页面不会自动写入。
      </p>
    </div>
    </RevealOnScroll>

    <RevealOnScroll as="div" :delay="180">
    <div v-if="chain?.graph.edges.length" class="panel fade-in" style="margin-top: 16px">
      <div class="panel-header"><h3 class="fx-underline">关系视图</h3></div>
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
    </RevealOnScroll>
  </template>
</template>
<style scoped>
.dimension-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:20px}.dimension-card{padding:16px;border:1px solid var(--border);border-radius:10px;background:var(--bg-elevated);transition:transform .3s cubic-bezier(.22,.61,.36,1),border-color .3s}.dimension-card:hover{transform:translateY(-3px);border-color:var(--border-bright)}@media(prefers-reduced-motion:reduce){.dimension-card:hover{transform:none}}.dimension-card h3{margin:0 0 10px;font-size:15px}.dimension-card strong{font-size:12px;color:var(--accent)}.dimension-card p,.detail-note{font-size:12px;color:var(--muted);line-height:1.8}.dimension-card small{color:var(--muted)}.hash-proof,.dimension-value{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px;line-height:1.8;font-family:monospace}.panel{overflow-x:auto}.panel :deep(a){overflow-wrap:anywhere}.panel>div>div:first-child{flex-wrap:wrap}@media(max-width:600px){.dimension-grid{grid-template-columns:1fr}.page-subtitle{flex-wrap:wrap}}
</style>
