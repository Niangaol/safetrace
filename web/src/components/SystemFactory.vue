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

// F 富化线的七个维度：直接显示关键词（不显示 F1/F2 编号），颜色即维度色
const DIMS = [
  { k: '论文', c: '#38bdf8' },
  { k: '资产', c: '#22c55e' },
  { k: 'POC', c: '#ff8800' },
  { k: 'CVSS', c: '#ff2d55' },
  { k: '修复', c: '#a78bfa' },
  { k: '校验', c: '#eab308' },
  { k: 'AI风险', c: '#818cf8' },
]
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

      <!-- 中央虚线数据流：唯一保留的动画，数据经它流过各站 -->
      <g class="pipes">
        <line x1="130" y1="110" x2="150" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="270" y1="110" x2="296" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="621" y1="110" x2="660" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
      </g>

      <!-- ═══ Y 监测线 ═══ -->
      <g transform="translate(10, 20)">
        <rect x="0" y="0" width="120" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="60" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">Y 监测线</text>
        <text x="60" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">采集 · 去重</text>

        <g font-family="JetBrains Mono" font-size="10" fill="#94a3b8">
          <text x="16" y="78">NVD · GHSA · arXiv</text>
          <text x="16" y="96">RSS · 漏洞库</text>
        </g>

        <text x="60" y="160" text-anchor="middle" fill="#38bdf8" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ n(props.rawItems) }} items</text>
      </g>

      <!-- ═══ T 分流 ═══ -->
      <g transform="translate(150, 20)">
        <rect x="0" y="0" width="120" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="60" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">Triage</text>
        <text x="60" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">分流路由</text>

        <path d="M22 66 L98 66 L70 92 L50 92 Z" fill="#0a0f1a" stroke="#2a4060" stroke-width="1" />

        <text x="60" y="130" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ pct(props.mergeRatio) }} merge</text>
        <text x="60" y="156" text-anchor="middle" fill="#a78bfa" font-size="12" font-weight="600" font-family="JetBrains Mono">{{ n(props.vulns) }} deduped</text>
      </g>

      <!-- ═══ F 富化线：不占整块，直接嵌在数据流线上，七个维度以关键词标注 ═══ -->
      <text x="455" y="40" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">F 富化线 · 七维加工</text>
      <text x="455" y="58" text-anchor="middle" fill="#22c55e" font-size="11" font-weight="600" font-family="JetBrains Mono">{{ cov(props.coverageRatio) }}% 覆盖</text>

      <g
        v-for="(d, i) in DIMS"
        :key="d.k"
        :transform="`translate(${296 + i * 52}, 0)`"
      >
        <circle cx="0" cy="104" r="9" :fill="d.c" opacity="0.9" />
        <text x="0" y="124" text-anchor="middle" :fill="d.c" font-size="11.5" font-weight="600" font-family="Inter">{{ d.k }}</text>
      </g>

      <!-- ═══ S 底座线 ═══ -->
      <g transform="translate(660, 20)">
        <rect x="0" y="0" width="130" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="65" y="26" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="700" font-family="JetBrains Mono">S 底座线</text>
        <text x="65" y="42" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">知识库 · 检索</text>

        <g v-for="i in 3" :key="i" :transform="`translate(35, ${58 + (i - 1) * 22})`">
          <ellipse cx="30" cy="0" rx="30" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <rect x="0" y="0" width="60" height="16" fill="#0a0f1a" stroke="#1e2d44" />
          <ellipse cx="30" cy="16" rx="30" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <rect x="14" y="6" width="30" height="3" rx="1" fill="#1e2d44" />
        </g>

        <text x="65" y="162" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="700" font-family="JetBrains Mono">{{ n(props.chunks) }} chunks</text>
        <text x="65" y="178" text-anchor="middle" fill="#64748b" font-size="10" font-family="Inter">pgvector · RRF</text>
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
  max-width: 900px;
  height: auto;
}

/* 中央虚线数据流：全图唯一的动画，其余均为静态 */
.pipe { animation: dashFlow 0.8s linear infinite; }
@keyframes dashFlow { to { stroke-dashoffset: -10; } }
</style>