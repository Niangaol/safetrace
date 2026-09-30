<script setup lang="ts">
// Pure SVG + CSS — 数据流管线
//
// 图上这些**数字**必须由外部传入真实指标（先前写死过 5,230 / 75.4% / 1,284 / 96% / 8,492，
// 与库里真实值对不上，一眼验伪）。数字取不到一律显示 "—"，不编造。
const props = withDefaults(
  defineProps<{
    rawItems?: number | null
    vulns?: number | null
    mergeRatio?: number | null
    coverageRatio?: number | null
    chunks?: number | null
  }>(),
  {
    rawItems: null,
    vulns: null,
    mergeRatio: null,
    coverageRatio: null,
    chunks: null,
  },
)

function n(v: number | null | undefined): string {
  return v === null || v === undefined ? '—' : v.toLocaleString()
}
function pct(v: number | null | undefined): string {
  return v === null || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`
}
function cov(v: number | null | undefined): string {
  return v === null || v === undefined ? '—' : `${(v * 100).toFixed(0)}%`
}

// F 富化线七个维度：卡片标题直接用关键词（不显示 F1–F7 编号）
const DIMS = [
  { k: '论文', c: '#38bdf8' },
  { k: '资产', c: '#22c55e' },
  { k: 'POC', c: '#ff8800' },
  { k: 'CVSS', c: '#ff2d55' },
  { k: '修复', c: '#a78bfa' },
  { k: '校验', c: '#eab308' },
  { k: 'AI风险', c: '#818cf8' },
]

// 证据链长度 = 真实覆盖率（只有面板数据能取到时才画，避免编造）
const chainWidth = () => {
  const r = props.coverageRatio ?? 0
  return Math.min(312, Math.round(312 * r))
}
</script>

<template>
  <div class="factory-wrap">
    <svg viewBox="0 0 880 220" class="factory-svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="nodeGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#14203a" />
          <stop offset="100%" stop-color="#0f1623" />
        </linearGradient>
      </defs>

      <!-- 中央虚线数据流：唯一保留的动画 -->
      <g class="pipes">
        <line x1="140" y1="110" x2="170" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="300" y1="110" x2="330" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="670" y1="110" x2="700" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
      </g>

      <!-- ═══ Y 监测线 ═══ -->
      <g transform="translate(10, 20)">
        <rect x="0" y="0" width="130" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="65" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">Y 监测线</text>
        <text x="65" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">采集 · 去重</text>

        <g font-family="JetBrains Mono" font-size="10" fill="#94a3b8">
          <text x="16" y="78">NVD · GHSA · arXiv</text>
          <text x="16" y="96">RSS · 漏洞库</text>
        </g>

        <text x="65" y="160" text-anchor="middle" fill="#38bdf8" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ n(props.rawItems) }} items</text>
      </g>

      <!-- ═══ T 分流 ═══ -->
      <g transform="translate(170, 20)">
        <rect x="0" y="0" width="130" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="65" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">Triage</text>
        <text x="65" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">分流路由</text>

        <path d="M24 66 L106 66 L76 92 L54 92 Z" fill="#0a0f1a" stroke="#2a4060" stroke-width="1" />

        <text x="65" y="130" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ pct(props.mergeRatio) }} merge</text>
        <text x="65" y="156" text-anchor="middle" fill="#a78bfa" font-size="12" font-weight="600" font-family="JetBrains Mono">{{ n(props.vulns) }} deduped</text>
      </g>

      <!-- ═══ F 富化线 · 盒式七维工坊（与其他模块同风格）═══ -->
      <g transform="translate(330, 20)">
        <rect x="0" y="0" width="340" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="170" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">F 富化线 · 七维工坊</text>
        <text x="170" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">EnrichAgent</text>

        <!-- 七维卡片：标题即维度关键词，颜色即维度色 -->
        <g
          v-for="(d, i) in DIMS"
          :key="d.k"
          :transform="`translate(${14 + i * 45}, 0)`"
        >
          <rect x="0" y="48" width="42" height="58" rx="6" fill="#0a0f1a" stroke="#1e2d44" stroke-width="1" />
          <circle cx="21" cy="62" r="3" :fill="d.c" :style="{ filter: `drop-shadow(0 0 4px ${d.c})` }" />
          <text x="21" y="85" text-anchor="middle" :fill="d.c" font-size="9.5" font-weight="700" font-family="Inter">{{ d.k }}</text>
        </g>

        <!-- evidence chain：长度 = 真实覆盖率 -->
        <text x="170" y="120" text-anchor="middle" fill="#64748b" font-size="9" font-family="JetBrains Mono">evidence chain</text>
        <rect x="14" y="128" width="312" height="3" rx="1.5" fill="#1e2d44" />
        <rect x="14" y="128" :width="chainWidth()" height="3" rx="1.5" fill="#818cf8" opacity="0.7" />

        <!-- 覆盖率徽标（真实值） -->
        <rect x="14" y="146" width="96" height="16" rx="4" fill="#0a0f1a" stroke="#22c55e" stroke-width="0.5" opacity="0.85" />
        <text x="62" y="158" text-anchor="middle" fill="#22c55e" font-size="10" font-weight="700" font-family="JetBrains Mono">{{ cov(props.coverageRatio) }}% cov</text>
      </g>

      <!-- ═══ S 底座线 ═══ -->
      <g transform="translate(700, 20)">
        <rect x="0" y="0" width="150" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="75" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">S 底座线</text>
        <text x="75" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">知识库 · 检索</text>

        <g v-for="i in 3" :key="i" :transform="`translate(42, ${58 + (i - 1) * 22})`">
          <ellipse cx="33" cy="0" rx="33" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <rect x="0" y="0" width="66" height="16" fill="#0a0f1a" stroke="#1e2d44" />
          <ellipse cx="33" cy="16" rx="33" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <rect x="16" y="6" width="34" height="3" rx="1" fill="#1e2d44" />
        </g>

        <text x="75" y="162" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ n(props.chunks) }} chunks</text>
        <text x="75" y="178" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">pgvector · RRF</text>
      </g>

      <!-- 管线图例 -->
      <text x="440" y="212" text-anchor="middle" fill="#64748b" font-size="11" font-family="Inter">Y 采集 → T 分流 → F 富化 → S 底座 · 循环运行中</text>
    </svg>
  </div>
</template>

<style scoped>
.factory-wrap {
  width: 100%;
  display: flex;
  justify-content: center;
}
.factory-svg {
  width: 100%;
  max-width: 980px;
  height: auto;
}

/* 中央虚线数据流：全图唯一的动画 */
.pipe { animation: dashFlow 0.8s linear infinite; }
@keyframes dashFlow { to { stroke-dashoffset: -10; } }
</style>