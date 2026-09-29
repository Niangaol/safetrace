<script setup lang="ts">
// Pure SVG + CSS — abstract data flow pipeline
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

      <!-- ═══ Pipeline connecting lines ═══ -->
      <g class="pipes">
        <line x1="125" y1="110" x2="175" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="285" y1="110" x2="335" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="695" y1="110" x2="745" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
        <line x1="855" y1="110" x2="860" y2="110" stroke="#2a4060" stroke-width="3" stroke-dasharray="6 4" class="pipe" />
      </g>

      <!-- ═══ Flowing particles ═══ -->
      <g class="particles">
        <circle cx="0" cy="110" r="2.5" fill="#38bdf8" class="particle p1" />
        <circle cx="0" cy="110" r="2.5" fill="#818cf8" class="particle p2" />
        <circle cx="0" cy="110" r="2.5" fill="#a78bfa" class="particle p3" />
      </g>

      <!-- ═══ STAGE 1: Y-line ═══ -->
      <g transform="translate(15, 20)">
        <rect x="0" y="0" width="110" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="55" y="24" text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700" font-family="JetBrains Mono">Y 监测线</text>
        <text x="55" y="38" text-anchor="middle" fill="#64748b" font-size="8" font-family="Inter">采集 · 去重</text>

        <g font-family="JetBrains Mono" font-size="8" fill="#64748b">
          <text x="14" y="62">NVD</text>
          <text x="14" y="80">GHSA</text>
          <text x="14" y="98">arXiv</text>
          <text x="14" y="116">RSS</text>
          <text x="14" y="134" fill="#475569">+3 sources</text>
        </g>
        <g class="src-lights">
          <circle cx="94" cy="59" r="2" fill="#22c55e" class="dot-pulse" />
          <circle cx="94" cy="77" r="2" fill="#22c55e" class="dot-pulse" style="animation-delay: .3s" />
          <circle cx="94" cy="95" r="2" fill="#22c55e" class="dot-pulse" style="animation-delay: .6s" />
          <circle cx="94" cy="113" r="2" fill="#22c55e" class="dot-pulse" style="animation-delay: .9s" />
        </g>

        <rect x="14" y="150" width="82" height="4" rx="2" fill="#1e2d44" />
        <rect x="14" y="150" width="82" height="4" rx="2" fill="#38bdf8" opacity="0.7" class="meter-fill" />
        <text x="55" y="168" text-anchor="middle" fill="#38bdf8" font-size="8" font-weight="600" font-family="JetBrains Mono">5,230 items</text>
      </g>

      <!-- ═══ STAGE 2: Triage ═══ -->
      <g transform="translate(175, 20)">
        <rect x="0" y="0" width="110" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="55" y="24" text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700" font-family="JetBrains Mono">Triage</text>
        <text x="55" y="38" text-anchor="middle" fill="#64748b" font-size="8" font-family="Inter">分流路由</text>

        <path d="M20 54 L90 54 L60 82 L50 82 Z" fill="#0a0f1a" stroke="#2a4060" stroke-width="1" />
        <line x1="55" y1="82" x2="55" y2="98" stroke="#2a4060" stroke-width="2" class="funnel-stream" />

        <rect x="20" y="103" width="22" height="3" rx="1.5" fill="#38bdf8" class="ch-bar c1" />
        <rect x="44" y="103" width="22" height="3" rx="1.5" fill="#818cf8" class="ch-bar c2" />
        <rect x="68" y="103" width="22" height="3" rx="1.5" fill="#22c55e" class="ch-bar c3" />

        <text x="55" y="128" text-anchor="middle" fill="#64748b" font-size="7" font-family="JetBrains Mono">hash + SimHash</text>
        <text x="55" y="148" text-anchor="middle" fill="#22c55e" font-size="9" font-weight="600" font-family="JetBrains Mono">75.4% merge</text>

        <rect x="14" y="160" width="82" height="4" rx="2" fill="#1e2d44" />
        <rect x="14" y="160" width="82" height="4" rx="2" fill="#a78bfa" opacity="0.6" class="meter-fill2" />
        <text x="55" y="176" text-anchor="middle" fill="#a78bfa" font-size="7" font-weight="600" font-family="JetBrains Mono">1,284 deduped</text>
      </g>

      <!-- ═══ STAGE 3: F-line (Enrichment) ═══ -->
      <g transform="translate(335, 20)">
        <rect x="0" y="0" width="360" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="180" y="24" text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700" font-family="JetBrains Mono">F 富化线 · 七维工坊</text>
        <text x="180" y="38" text-anchor="middle" fill="#64748b" font-size="8" font-family="Inter">EnrichAgent</text>

        <!-- 7 enrichment nodes -->
        <g v-for="(st, i) in [
          { x: 20, label: 'F1', name: '论文', color: '#38bdf8' },
          { x: 68, label: 'F2', name: '资产', color: '#22c55e' },
          { x: 116, label: 'F3', name: 'POC', color: '#ff8800' },
          { x: 164, label: 'F4', name: 'CVSS', color: '#ff2d55' },
          { x: 212, label: 'F5', name: '修复', color: '#a78bfa' },
          { x: 260, label: 'F6', name: '校验', color: '#eab308' },
          { x: 308, label: 'AI', name: '风险', color: '#818cf8' },
        ]" :key="i" :transform="`translate(${st.x}, 50)`">
          <rect x="0" y="0" width="34" height="56" rx="6" fill="#0a0f1a" stroke="#1e2d44" stroke-width="1" />
          <circle cx="17" cy="14" r="3" :fill="st.color" class="station-light" :style="{ animationDelay: i * 0.2 + 's', filter: 'drop-shadow(0 0 4px ' + st.color + ')' }" />
          <rect x="9" y="22" width="16" height="14" rx="3" fill="#0a0f1a" :stroke="st.color" stroke-width="0.5" opacity="0.4" />
          <text x="17" y="46" text-anchor="middle" :fill="st.color" font-size="8" font-weight="700" font-family="JetBrains Mono">{{ st.label }}</text>
          <text x="17" y="54" text-anchor="middle" fill="#475569" font-size="6" font-family="Inter">{{ st.name }}</text>
        </g>

        <!-- evidence chain -->
        <rect x="20" y="118" width="320" height="3" rx="1.5" fill="#1e2d44" />
        <rect x="20" y="118" width="320" height="3" rx="1.5" fill="#818cf8" opacity="0.7" class="evidence-fill" />
        <text x="180" y="136" text-anchor="middle" fill="#22c55e" font-size="8" font-weight="600" font-family="JetBrains Mono">evidence chain: 100% · 7/7 dims</text>

        <!-- data flow strip -->
        <rect x="20" y="148" width="320" height="8" rx="4" fill="#0a0f1a" stroke="#1e2d44" />
        <g class="flow-strip"><rect x="0" y="0" width="10" height="8" rx="2" fill="#818cf8" opacity="0.6" /></g>
        <g class="flow-strip2"><rect x="0" y="0" width="10" height="8" rx="2" fill="#38bdf8" opacity="0.6" /></g>

        <!-- status badges -->
        <g font-family="JetBrains Mono" font-size="7">
          <rect x="20" y="166" width="64" height="11" rx="3" fill="#0a0f1a" stroke="#22c55e" stroke-width="0.5" opacity="0.8" />
          <text x="52" y="174" text-anchor="middle" fill="#22c55e">96% cov</text>
          <rect x="92" y="166" width="66" height="11" rx="3" fill="#0a0f1a" stroke="#eab308" stroke-width="0.5" opacity="0.8" />
          <text x="125" y="174" text-anchor="middle" fill="#eab308">◇ mock F2</text>
          <rect x="166" y="166" width="70" height="11" rx="3" fill="#0a0f1a" stroke="#ff8800" stroke-width="0.5" opacity="0.8" />
          <text x="201" y="174" text-anchor="middle" fill="#ff8800">⚠ degr F3</text>
          <rect x="244" y="166" width="76" height="11" rx="3" fill="#0a0f1a" stroke="#ff2d55" stroke-width="0.5" opacity="0.8" />
          <text x="282" y="174" text-anchor="middle" fill="#ff2d55">! conflict F6</text>
        </g>
      </g>

      <!-- ═══ STAGE 4: S-line ═══ -->
      <g transform="translate(745, 20)">
        <rect x="0" y="0" width="110" height="180" rx="10" fill="url(#nodeGrad)" stroke="#2a4060" stroke-width="1.5" />
        <text x="55" y="24" text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700" font-family="JetBrains Mono">S 底座线</text>
        <text x="55" y="38" text-anchor="middle" fill="#64748b" font-size="8" font-family="Inter">知识库 · 索引</text>

        <g v-for="i in 3" :key="i" :transform="`translate(25, ${50 + (i-1)*24})`">
          <ellipse cx="30" cy="0" rx="30" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <rect x="0" y="0" width="60" height="16" fill="#0a0f1a" stroke="#1e2d44" />
          <ellipse cx="30" cy="16" rx="30" ry="6" fill="#0a0f1a" stroke="#1e2d44" />
          <circle cx="10" cy="8" r="1.5" fill="#38bdf8" class="dot-pulse" :style="{ animationDelay: i * 0.4 + 's' }" />
          <rect x="18" y="6" width="30" height="3" rx="1" fill="#1e2d44" />
        </g>

        <g class="vector-dots" transform="translate(25, 130)">
          <circle cx="10" cy="8" r="1.5" fill="#38bdf8" />
          <circle cx="25" cy="5" r="1.5" fill="#818cf8" />
          <circle cx="40" cy="10" r="1.5" fill="#38bdf8" />
          <circle cx="55" cy="6" r="1.5" fill="#818cf8" />
        </g>

        <text x="55" y="160" text-anchor="middle" fill="#22c55e" font-size="9" font-weight="600" font-family="JetBrains Mono">8,492 chunks</text>
        <text x="55" y="174" text-anchor="middle" fill="#475569" font-size="6" font-family="Inter">pgvector · 1024-dim · RRF</text>
      </g>

      <!-- ═══ Pipeline label ═══ -->
      <text x="440" y="210" text-anchor="middle" fill="#475569" font-size="9" font-family="Inter">Y 采集 → T 分流 → F 富化 → S 底座 · 循环运行中</text>
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
  max-width: 880px;
  height: auto;
}

/* pipe flow */
.pipe { animation: dashFlow 0.8s linear infinite; }
@keyframes dashFlow { to { stroke-dashoffset: -10; } }

/* flowing particles */
.particle.p1 { animation: particleMove 4s linear infinite; }
.particle.p2 { animation: particleMove 4s linear infinite; animation-delay: 1.3s; }
.particle.p3 { animation: particleMove 4s linear infinite; animation-delay: 2.6s; }
@keyframes particleMove {
  0%   { transform: translateX(125px); opacity: 0; }
  5%   { opacity: 1; }
  18%  { transform: translateX(285px); }
  38%  { transform: translateX(695px); }
  55%  { transform: translateX(855px); }
  95%  { opacity: 1; }
  100% { transform: translateX(860px); opacity: 0; }
}

/* station lights */
.station-light { animation: stationPulse 2s ease-in-out infinite; }
@keyframes stationPulse {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 1; }
}

/* evidence fill */
.evidence-fill {
  animation: evidenceGrow 3s ease-in-out infinite;
  transform-origin: left;
}
@keyframes evidenceGrow {
  0% { transform: scaleX(0); }
  50% { transform: scaleX(1); }
  100% { transform: scaleX(1); opacity: 0.5; }
}

/* flow strip */
.flow-strip { animation: stripMove 3s linear infinite; }
@keyframes stripMove {
  0% { transform: translate(20px, 148px); opacity: 0; }
  10% { opacity: 0.6; }
  90% { opacity: 0.6; }
  100% { transform: translate(330px, 148px); opacity: 0; }
}
.flow-strip2 { animation: stripMove 3s linear infinite; animation-delay: 1.5s; }

/* meter bars */
.meter-fill {
  animation: meterPulse 3s ease-in-out infinite;
  transform-origin: left;
}
.meter-fill2 {
  animation: meterPulse 3s ease-in-out infinite;
  transform-origin: left;
  animation-delay: 1s;
}
@keyframes meterPulse {
  0%, 100% { transform: scaleX(0.7); }
  50% { transform: scaleX(1); }
}

/* channel bars */
.ch-bar.c1 { animation: chPulse 2s ease-in-out infinite; }
.ch-bar.c2 { animation: chPulse 2s ease-in-out infinite; animation-delay: 0.7s; }
.ch-bar.c3 { animation: chPulse 2s ease-in-out infinite; animation-delay: 1.3s; }
@keyframes chPulse {
  0%, 100% { opacity: 0.3; transform: scaleX(0.5); }
  50% { opacity: 1; transform: scaleX(1); }
}

/* funnel stream */
.funnel-stream { animation: funnelPulse 1.5s ease-in-out infinite; }
@keyframes funnelPulse {
  0%, 100% { opacity: 0.2; }
  50% { opacity: 1; }
}

/* pulse dots */
.dot-pulse { animation: dotPulse 1.5s ease-in-out infinite; }
@keyframes dotPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* vector dots */
.vector-dots { animation: vectorFloat 4s ease-in-out infinite; }
@keyframes vectorFloat {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-3px); }
}
</style>
