<script setup lang="ts">
/** 全局装饰背景：粒子 + 连线 + 冷色光束 + 雷达涟漪。纯装饰，aria-hidden。 */
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { AmbientEngine } from './ambient-engine'
import { getMotionIntensity, onMotionIntensityChange } from './motion-prefs'

const canvas = ref<HTMLCanvasElement | null>(null)
let engine: AmbientEngine | null = null
let resizeTimer: ReturnType<typeof setTimeout> | undefined
let unbindMotion: (() => void) | undefined
let scrollHandler: (() => void) | undefined
let scrollRaf: number | undefined

function measure() {
  if (!engine) return
  engine.resize(globalThis.innerWidth, globalThis.innerHeight)
}

function onResize() {
  if (resizeTimer !== undefined) globalThis.clearTimeout(resizeTimer)
  resizeTimer = globalThis.setTimeout(() => { resizeTimer = undefined; measure() }, 150)
}

function onVisibility() { engine?.syncVisibility() }

function updateIntensityByScroll() {
  if (!engine) return
  const scrollY = globalThis.scrollY || 0
  const vh = globalThis.innerHeight || window.innerHeight || 1
  const threshold = vh * 0.5
  const current = getMotionIntensity()
  let target: typeof current = current === 'off' ? 'off' : scrollY < threshold ? 'full' : scrollY < vh ? 'low' : 'low'
  if (engine && engine['intensity'] !== undefined) {
    // rely on setIntensity via prefs? easier: set directly
  }
  // force via setIntensity with target
  if (engine) {
    const eng = engine as any
    if (eng.intensity !== target && target !== 'off') {
      engine.setIntensity(target as any)
    } else if (target === 'off' && current !== 'off') {
      engine.setIntensity('off')
    } else if (eng.intensity !== target) {
      engine.setIntensity(target as any)
    }
  }
}

function scheduleScroll() {
  if (scrollRaf !== undefined) return
  scrollRaf = requestAnimationFrame(() => {
    scrollRaf = undefined
    updateIntensityByScroll()
  })
}

onMounted(() => {
  const element = canvas.value
  if (!element) return
  engine = new AmbientEngine({ canvas: element, intensity: getMotionIntensity() })
  measure()
  engine.start()
  globalThis.addEventListener('resize', onResize, { passive: true })
  globalThis.document.addEventListener('visibilitychange', onVisibility)
  unbindMotion = onMotionIntensityChange(() => { engine?.setIntensity(getMotionIntensity()); engine?.syncVisibility(); scheduleScroll() })
  globalThis.addEventListener('scroll', scheduleScroll, { passive: true })
  scheduleScroll()
  if (import.meta.env.DEV) (globalThis as unknown as { __safetraceEffects?: unknown }).__safetraceEffects = { stats: () => engine?.stats() }
})
onBeforeUnmount(() => {
  if (resizeTimer !== undefined) globalThis.clearTimeout(resizeTimer)
  globalThis.removeEventListener('resize', onResize)
  globalThis.removeEventListener('visibilitychange', onVisibility)
  globalThis.removeEventListener('scroll', scheduleScroll)
  unbindMotion?.()
  if (scrollRaf !== undefined) { cancelAnimationFrame(scrollRaf); scrollRaf = undefined }
  engine?.dispose()
  engine = null
  if (import.meta.env.DEV) delete (globalThis as unknown as { __safetraceEffects?: unknown }).__safetraceEffects
})
</script>

<template>
  <canvas ref="canvas" class="ambient-canvas" aria-hidden="true"></canvas>
</template>
