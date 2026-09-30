<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import { getJson } from '../api'
import TerminalWindow from '../components/TerminalWindow.vue'
import type { EvidenceResponse, GraphNode, VulnItem } from '../types'

const props = defineProps<{ id: string }>()
const router = useRouter()

const vuln = ref<VulnItem | null>(null)
const chain = ref<EvidenceResponse | null>(null)
const openDims = ref<Set<string>>(new Set())
const error = ref('')
const loading = ref(true)
const hoveredNode = ref<string | null>(null)

const GRAPH_V = 520
const GRAPH_R: number[] = [0, 78, 138, 186]
const GRAPH_C = GRAPH_V / 2

const TYPE_COLOR: Record<string, string> = {
  vuln: '#38bdf8', cve: '#38bdf8', cwe: '#f59e0b', cpe: '#22c55e',
  asset: '#22c55e', product: '#34d399', company: '#a78bfa',
  exploit: '#ff5470', exploitdb: '#ff5470', patch: '#4ade80', fix: '#4ade80',
  ref: '#94a3b8', reference: '#94a3b8', knowledge: '#eab308',
  mitre: '#f472b6', tactic: '#f472b6', weapon: '#ff8800',
}
function nodeColor(type: string): string {
  return TYPE_COLOR[type?.toLowerCase()] || '#94a3b8'
}
function trunc(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}
function isVulnId(id?: string): boolean {
  return !!id && /^CVE-\d|^GHSA-|^CVE-/.test(id.toUpperCase())
}

interface LayNode {
  id: string
  label: string
  type: string
  x: number
  y: number
  ring: number
}
interface LayEdge {
  src: string
  dst: string
  rel: string
  type?: string
  x1: number; y1: number; x2: number; y2: number
}
interface GraphLayout {
  nodes: LayNode[]
  edges: LayEdge[]
  centerId: string
}

const graphLayout = computed<GraphLayout | null>(() => {
  const g = chain.value?.graph
  const idCmp = vuln.value?.cve_id || vuln.value?.id
  if (!g || !g.nodes.length) return null
  const nodes: GraphNode[] = g.nodes
  const edges = g.edges
  if (!edges.length) return null

  let root = nodes.find((n) => n.id === idCmp || n.label === idCmp)
  if (!root) {
    const deg = new Map<string, number>()
    for (const e of edges) {
      deg.set(e.src, (deg.get(e.src) || 0) + 1)
      deg.set(e.dst, (deg.get(e.dst) || 0) + 1)
    }
    let best = ''
    let bd = -1
    deg.forEach((d, id) => { if (d > bd) { bd = d; best = id } })
    root = nodes.find((n) => n.id === best) ?? nodes[0]
  }

  const adj: Record<string, string[]> = {}
  for (const e of edges) {
    ;(adj[e.src] ??= []).push(e.dst)
    ;(adj[e.dst] ??= []).push(e.src)
  }
  const ring: Record<string, number> = { [root.id]: 0 }
  const queue = [root.id]
  while (queue.length) {
    const cur = queue.shift()!
    const r = ring[cur]
    for (const nb of adj[cur] ?? []) {
      if (!(nb in ring) && ring[cur] < 3) { ring[nb] = r + 1; queue.push(nb) }
    }
  }
  for (const n of nodes) if (!(n.id in ring)) ring[n.id] = 3

  const pos: Record<string, { x: number; y: number }> = {}
  const byRing: Record<number, string[]> = { 0: [], 1: [], 2: [], 3: [] }
  for (const n of nodes) byRing[ring[n.id]].push(n.id)
  for (const rk of [0, 1, 2, 3]) {
    const ids = byRing[rk]
    const count = ids.length
    ids.forEach((id, i) => {
      if (rk === 0) { pos[id] = { x: GRAPH_C, y: GRAPH_C }; return }
      const base = (i * 2 * Math.PI) / count
      let hash = 0
      for (const ch of id) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0
      const angle = base + (hash % 7) * 0.06 - 0.18
      pos[id] = {
        x: GRAPH_C + GRAPH_R[rk] * Math.cos(angle),
        y: GRAPH_C + GRAPH_R[rk] * Math.sin(angle),
      }
    })
  }

  const outNodes: LayNode[] = nodes.map((n) => ({
    id: n.id,
    label: n.label || n.id,
    type: n.type || 'ref',
    ring: ring[n.id],
    x: pos[n.id]?.x ?? GRAPH_C,
    y: pos[n.id]?.y ?? GRAPH_C,
  }))
  const outEdges: LayEdge[] = edges
    .filter((e) => pos[e.src] && pos[e.dst])
    .map((e) => ({
      src: e.src, dst: e.dst, rel: e.rel, type: e.type,
      x1: pos[e.src].x, y1: pos[e.src].y,
      x2: pos[e.dst].x, y2: pos[e.dst].y,
    }))
  return { nodes: outNodes, edges: outEdges, centerId: root.id }
})

const hoverLabel = computed(
  () => graphLayout.value?.nodes.find((n) => n.id === hoveredNode.value)?.label ?? '',
)
const hoverRels = computed(() => {
  const id = hoveredNode.value
  if (!id || !graphLayout.value) return []
  const rels: string[] = []
  for (const e of graphLayout.value.edges) {
    if (e.src === id || e.dst === id) rels.push(`${e.src} ${e.rel} ${e.dst}`)
  }
  return rels.slice(0, 8)
})

function goNode(n: LayNode) {
  router.push(entityTo(n.id))
}

/** 某节点在图里的类型（小写）；用于判断它是漏洞还是其它实体 */
function nodeTypeOf(id: string): string {
  return graphLayout.value?.nodes.find((n) => n.id === id)?.type?.toLowerCase() ?? ''
}

/**
 * 终端/图里的**每个**实体都给出真实去处，终端里不再有"点不动的死文本"：
 * - 漏洞实体（CVE-/GHSA- 前缀，或图里 type 为 vuln/cve）→ 该漏洞详情页；
 * - 其它实体（CWE、产品、公司、论文…）→ 情报库按该实体检索（`/intel?q=`）。
 */
function isVulnEntity(id: string): boolean {
  if (isVulnId(id)) return true
  const t = nodeTypeOf(id)
  return t === 'vuln' || t === 'cve'
}
function entityTo(id: string): string {
  return isVulnEntity(id)
    ? `/intel/${encodeURIComponent(id)}`
    : `/intel?q=${encodeURIComponent(id)}`
}
function entityHint(id: string): string {
  return isVulnEntity(id) ? `查看漏洞详情：${id}` : `在情报库检索「${id}」`
}

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
      <p class="muted" style="font-size: 12px; margin-top: 0">
        每个字段都记录来源 URL、原文片段与抓取时间，可逐条溯源核对。
      </p>

      <div v-for="e in chain?.enrichments ?? []" :key="e.dimension" style="margin-bottom: 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden">
        <div style="display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--bg-elevated); cursor: pointer" @click="toggle(e.dimension)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; color: var(--accent); flex-shrink: 0">
            <path :d="DIM_ICON[e.dimension] || 'M12 2L2 7v10l10 5 10-5V7L12 2z'" />
          </svg>
          <strong style="min-width: 100px">{{ DIM_LABEL[e.dimension] ?? e.dimension }}</strong>
          <span class="badge info">置信度 {{ (e.confidence * 100).toFixed(0) }}%</span>
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

      <!-- 未富化状态：**如实说明**，不留空白也不假装已富化。
           真实采集了 1400+ 条，但富化逐条走 LLM（单条约 7 秒、约 ¥0.01），
           全量跑代价高，所以只对代表性样本做了富化。
           演示时若被问到"为什么只有这些有富化"，这段文案就是答案。 -->
      <div v-if="!chain?.enrichments?.length" class="notice" style="margin-top: 8px">
        <strong>本条目尚未富化</strong>（当前库中 1451 条漏洞里 94 条已完成 7 维富化）。
        <div class="muted" style="font-size: 12px; margin-top: 6px; line-height: 1.7">
          富化需要逐条调用 LLM（约 7 秒/条），因此只对**代表性样本**做了富化，
          其余保留采集到的原始描述与来源链接 —— 上方内容与引用均来自真实采集，未编造。<br />
          补齐方式：<code>POST /api/v1/enrich/backfill</code>
          或 <code>python -m aiintel.cli enrich --vuln-id &lt;id&gt;</code>。
        </div>
      </div>
    </div>

    <div v-if="graphLayout" class="panel fade-in" style="margin-top: 16px">
      <div class="panel-header">
        <h3>关系视图</h3>
        <span class="badge-count">{{ graphLayout.nodes.length }} 节点 · {{ graphLayout.edges.length }} 关系</span>
      </div>
      <p class="muted" style="font-size: 12px; margin-top: 0">
        蛛网关系图为主视图：悬停节点高亮相连关系、点击节点可跳转（CVE/GHSA 等漏洞进详情页，CWE / 产品 / 公司等实体进情报库检索）；右侧关系表以 Linux 终端窗呈现，滚轮可滚动、悬停行与图中联动、**每个实体名都可点击追溯**、标题栏 ⤢ 可放大查看（Esc 还原）。
      </p>

      <div class="rel-layout fade-in">
        <!-- 主视图：蛛网关系图 -->
        <div class="rel-graph-side">
          <div class="rel-graph-title">蛛网关系图</div>
          <div class="graph-wrap">
            <svg :viewBox="`0 0 ${GRAPH_V} ${GRAPH_V}`" class="rel-graph" role="img" aria-label="漏洞关系蛛网图">
              <defs>
                <radialGradient id="relCore" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stop-color="rgba(56, 189, 248, 0.14)" />
                  <stop offset="100%" stop-color="rgba(56, 189, 248, 0)" />
                </radialGradient>
              </defs>
              <circle :cx="GRAPH_C" :cy="GRAPH_C" :r="GRAPH_R[3]" fill="url(#relCore)" />
              <circle
                v-for="r in GRAPH_R.slice(1)"
                :key="r"
                :cx="GRAPH_C" :cy="GRAPH_C" :r="r"
                class="rel-ring"
              />
              <line
                v-for="i in 8" :key="'spoke' + i"
                :x1="GRAPH_C" :y1="GRAPH_C"
                :x2="GRAPH_C + GRAPH_R[3] * Math.cos((i * Math.PI) / 4)"
                :y2="GRAPH_C + GRAPH_R[3] * Math.sin((i * Math.PI) / 4)"
                class="rel-spoke"
              />

              <g v-for="(e, i) in graphLayout.edges" :key="'e' + i">
                <line
                  :x1="e.x1" :y1="e.y1" :x2="e.x2" :y2="e.y2"
                  class="rel-edge"
                  :class="{
                    dim: hoveredNode && hoveredNode !== e.src && hoveredNode !== e.dst,
                    hi: hoveredNode === e.src || hoveredNode === e.dst,
                  }"
                />
              </g>

              <g
                v-for="n in graphLayout.nodes"
                :key="n.id"
                class="rel-node"
                :class="{ dimNode: hoveredNode && hoveredNode !== n.id, hot: hoveredNode === n.id }"
                @mouseenter="hoveredNode = n.id"
                @mouseleave="hoveredNode = null"
                @click="goNode(n)"
              >
                <circle
                  :cx="n.x" :cy="n.y"
                  :r="n.id === graphLayout.centerId ? 22 : 11"
                  fill="rgba(10, 15, 26, 0.9)"
                  :stroke="nodeColor(n.type)"
                  :stroke-width="hoveredNode === n.id ? 2.5 : 1.5"
                />
                <circle
                  :cx="n.x" :cy="n.y"
                  :r="hoveredNode === n.id ? 15 : 9"
                  fill="none" :stroke="nodeColor(n.type)"
                  opacity="0.5"
                />
                <text
                  :x="n.x" :y="n.y - (n.id === graphLayout.centerId ? 26 : 14)"
                  text-anchor="middle"
                  class="rel-label"
                  :fill="hoveredNode === n.id ? '#f1f5f9' : '#94a3b8'"
                >
                  {{ trunc(n.label, 14) }}
                </text>
              </g>
            </svg>
          </div>

          <div v-if="hoveredNode && hoverRels.length" class="rel-info">
            <strong style="color: #e2e8f0">{{ trunc(hoverLabel, 24) }}</strong>
            <div class="badge info" style="margin-left: 8px">{{ hoverRels.length }} 条相连关系</div>
            <div class="rel-rels">
              <span v-for="r in hoverRels" :key="r" class="rel-chip">{{ r }}</span>
            </div>
          </div>
        </div>

        <!-- 辅助视图：Linux 终端窗（滚轮滚动，可点大查看） -->
        <TerminalWindow
          class="rel-term"
          title="safe_trace@intel: ~/relations"
          :status="`▮ ${graphLayout.edges.length} 条关系 · 实体名可点击追溯 · 悬停行联动图中高亮 · ⤢ 放大 / Esc 还原`"
        >
          <div
            v-for="(e, i) in graphLayout.edges"
            :key="i"
            class="lnx-line"
            @mouseenter="hoveredNode = e.dst"
            @mouseleave="hoveredNode = null"
          >
            <span class="lnx-arrow">▸</span>
            <RouterLink
              class="lnx-src lnx-link"
              :to="entityTo(e.src)"
              :title="entityHint(e.src)"
            >{{ e.src }}</RouterLink>
            <span class="lnx-rel">{{ e.rel }}</span>
            <RouterLink
              class="lnx-dst lnx-link"
              :to="entityTo(e.dst)"
              :title="entityHint(e.dst)"
            >{{ e.dst }}</RouterLink>
            <span class="lnx-type">{{ e.type }}</span>
          </div>
        </TerminalWindow>
      </div>
    </div>
  </template>
</template>

<style scoped>
/* 关系视图：蛛网图为主（大），关系表为辅（Linux 窗口，右侧） */
.rel-layout {
  display: flex;
  gap: 20px;
  align-items: stretch;
  /* 终端不贴边：右侧再留 6px 内缩，配合 main 的外边距，离屏幕边缘有足够呼吸 */
  padding-right: 6px;
}
.rel-graph-side {
  flex: 1 1 0;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.rel-graph-title {
  font-size: 12px;
  font-weight: 600;
  color: #e2e8f0;
  margin-bottom: 6px;
}
.graph-wrap {
  display: flex;
  justify-content: center;
  flex: 1;
}
.rel-graph {
  width: 100%;
  max-width: 560px;
  height: auto;
}
.rel-ring {
  fill: none;
  stroke: rgba(56, 189, 248, 0.12);
  stroke-width: 1;
}
.rel-spoke {
  stroke: rgba(56, 189, 248, 0.08);
  stroke-width: 1;
}
.rel-edge {
  stroke: rgba(148, 197, 255, 0.28);
  stroke-width: 1.2;
  transition: all 0.2s;
}
.rel-edge.hi {
  stroke: #38bdf8;
  stroke-width: 2;
  filter: drop-shadow(0 0 4px rgba(56, 189, 248, 0.6));
}
.rel-edge.dim {
  stroke: rgba(148, 197, 255, 0.07);
}
.rel-node {
  cursor: pointer;
}
.rel-node.dimNode {
  opacity: 0.3;
}
.rel-node.hot {
  filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.6));
}
.rel-label {
  font-size: 10px;
  font-family: 'JetBrains Mono', monospace;
  paint-order: stroke;
  stroke: rgba(6, 18, 31, 0.92);
  stroke-width: 3px;
  transition: fill 0.2s;
}
.rel-info {
  margin-top: 10px;
  padding: 10px 14px;
  border: 1px solid rgba(56, 189, 248, 0.25);
  border-radius: 10px;
  background: rgba(15, 23, 42, 0.6);
  font-size: 12px;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.rel-rels {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-left: auto;
}
.rel-chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: #7dd3fc;
  background: rgba(56, 189, 248, 0.1);
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: 6px;
  padding: 2px 8px;
}

/* Linux 窗口风的关系表 */
/* 终端窗：高度与左侧蛛网图**严格同高**。
   .rel-layout 是 align-items: stretch 的 flex 行，.rel-term 作为 stretch 项被拉到
   与 .rel-graph-side（标题 + 蛛网图）同高；.tw-body 再用 flex:1 吃掉标题栏以外的高度
   并自己滚动，所以终端底边与蛛网图底边对齐。 */
.rel-term {
  flex: 0 0 clamp(340px, 32vw, 470px);
  max-width: 100%;
  align-self: stretch;
}
.rel-term :deep(.tw-body) {
  flex: 1;
  min-height: 0;
  max-height: none;
}
.lnx-line {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  border-bottom: 1px dashed rgba(42, 64, 96, 0.35);
  transition: background 0.15s;
}
.lnx-line:hover {
  background: rgba(56, 189, 248, 0.09);
}
.lnx-arrow { color: #38bdf8; font-size: 9px; flex-shrink: 0; }
.lnx-src,
.lnx-dst {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex-shrink: 1;
}
.lnx-src { max-width: 38%; }
.lnx-dst { max-width: 34%; }
/* 终端里的实体名：可点击（跳漏洞详情或情报库检索）。
   用 <a> 而不是 <button>：语义正确、可 Tab 聚焦、状态栏能看到真实去处。
   同时要抵消全局 button/:hover 的放大位移 —— 行内小链接跟着放大既晃眼难点。 */
.lnx-link {
  color: #9cc8f2;
  border-bottom: 1px dashed rgba(125, 211, 252, 0.4);
  padding-bottom: 1px;
  cursor: pointer;
  transition: color 0.15s, background 0.15s, border-color 0.15s;
}
.lnx-link:hover {
  color: #e0f2fe;
  background: rgba(56, 189, 248, 0.14);
  border-bottom-color: #bae6fd;
}
.lnx-link:focus-visible {
  outline: 2px solid rgba(125, 211, 252, 0.7);
  outline-offset: 1px;
  border-radius: 2px;
}
.lnx-rel {
  color: #f0b429;
  background: rgba(240, 180, 41, 0.1);
  border: 1px solid rgba(240, 180, 41, 0.25);
  border-radius: 4px;
  padding: 0 5px;
  font-size: 10px;
  flex-shrink: 0;
}
.lnx-type {
  color: #64748b;
  font-size: 10px;
  margin-left: auto;
  flex-shrink: 0;
}
@media (max-width: 900px) {
  .rel-layout {
    flex-direction: column;
  }
  /* 纵向堆叠时 stretch 不再管高度，给终端一个明确的高，够长好读 */
  .rel-term {
    flex: 0 0 auto;
    height: 360px;
  }
}
</style>
