<script setup lang="ts">
import ThreatGlobe from './ThreatGlobe.vue'
</script>

<template>
  <section class="hero">
    <div class="hero-bg">
      <div class="hero-grid"></div>
      <div class="orb orb-a"></div>
      <div class="orb orb-b"></div>
      <div class="orb orb-c"></div>
      <div class="globe-viewport">
        <ThreatGlobe />
      </div>
    </div>
    <div class="hero-content">
      <div class="hero-badge">
        <span class="hero-badge-dot"></span>
        AI Security Intelligence
      </div>
      <h1 class="hero-title">SafeTrace</h1>
      <p class="hero-subtitle">智能体驱动的 AI 安全知识情报系统</p>
      <p class="hero-desc">
        多源采集 · 七维富化 · 证据链追溯 · 混合检索 · 自动降级
      </p>
    </div>
  </section>
</template>

<style scoped>
.hero {
  position: relative;
  container-type: size;
  text-align: center;
  padding: 88px 24px 96px;
  min-height: 420px;
  border-radius: 16px;
  overflow: hidden;
  margin: 0 0 28px;
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
.globe-viewport {
  position: absolute;
  top: 50%;
  left: 50%;
  width: min(100cqw, calc(100cqh + 136px));
  aspect-ratio: 1 / 1;
  transform: translate(-50%, -50%);
  z-index: 0;
  pointer-events: none;
  user-select: none;
}
.globe-viewport > * {
  pointer-events: none;
}
.hero-content {
  position: relative;
  z-index: 1;
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
  display: block;
  text-align: center;
  background-image:
    linear-gradient(
      102deg,
      transparent 20%,
      rgba(255, 255, 255, 0.55) 42%,
      #ffffff 50%,
      rgba(255, 255, 255, 0.55) 58%,
      transparent 80%
    ),
    linear-gradient(
      178deg,
      #ffffff 0%,
      #e8eef7 18%,
      #9cc8f2 42%,
      #64b5f6 62%,
      #1e88e5 82%,
      #1565c0 100%
    );
  background-size: 240px 100%, 100% 100%;
  background-repeat: no-repeat, no-repeat;
  background-position: -300px 0, 0 0;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
  text-shadow: 0 0 40px rgba(56, 189, 248, 0.35), 0 0 90px rgba(56, 189, 248, 0.2);
  animation: htSweep 6s ease-in-out infinite;
}
@keyframes htSweep {
  0%, 15% { background-position: -300px 0, 0 0; }
  60% { background-position: 900px 0, 0 0; }
  100% { background-position: 1100px 0, 0 0; }
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
  margin: 0;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.5px;
}
@media (max-width: 700px) {
  .hero { padding: 60px 18px 72px; min-height: 340px; }
  .hero-title { font-size: 52px; }
  .hero-subtitle { font-size: 17px; }
}
</style>
