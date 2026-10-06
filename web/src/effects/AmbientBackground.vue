<script setup lang="ts">
/** 全局装饰背景：粒子 + 连线 + 冷色光束 + 雷达涟漪。纯装饰，aria-hidden。 */
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { AmbientEngine } from './ambient-engine'
import { getMotionIntensity, onMotionIntensityChange } from './motion-prefs'

const canvas = ref<HTMLCanvasElement | null>(null)
let engine: AmbientEngine | null = null
let resizeTimer: ReturnType<typeof setTimeout> | undefined
let unbindMotion: (() => void) | undefined

function measure() {
  if (!engine) return
  engine.resize(globalThis.innerWidth, globalThis.innerHeight)
}
function onResize() {
  if (resizeTimer !== undefined) globalThis.clearTimeout(resizeTimer)
  resizeTimer = globalThis.setTimeout(() => { resizeTimer = undefined; measure() }, 150)
}
function onVisibility() { engine?.syncVisibility() }

onMounted(() => {
  const element = canvas.value
  if (!element) return
  engine = new AmbientEngine({ canvas: element, intensity: getMotionIntensity() })
  measure()
  engine.start()
  globalThis.addEventListener('resize', onResize, { passive: true })
  globalThis.document.addEventListener('visibilitychange', onVisibility)
  unbindMotion = onMotionIntensityChange(() => { engine?.setIntensity(getMotionIntensity()); engine?.syncVisibility() })
  if (import.meta.env.DEV) (globalThis as unknown as { __safetraceEffects?: unknown }).__safetraceEffects = { stats: () => engine?.stats() }
})
onBeforeUnmount(() => {
  if (resizeTimer !== undefined) globalThis.clearTimeout(resizeTimer)
  globalThis.removeEventListener('resize', onResize)
  globalThis.document.removeEventListener('visibilitychange', onVisibility)
  unbindMotion?.()
  engine?.dispose()
  engine = null
  if (import.meta.env.DEV) delete (globalThis as unknown as { __safetraceEffects?: unknown }).__safetraceEffects
})
</script>

<template>
  <canvas ref="canvas" class="ambient-canvas" aria-hidden="true"></canvas>
</template>
