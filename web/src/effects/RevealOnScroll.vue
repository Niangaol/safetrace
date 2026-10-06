<script setup lang="ts">
/** 进入视口时错落入场；不支持 IO / 减少动效时直接显示，绝不长期隐藏内容。 */
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { getMotionIntensity } from './motion-prefs'

const props = withDefaults(defineProps<{ as?: string; delay?: number; threshold?: number; once?: boolean; variant?: 'up' | 'left' | 'scale' }>(), { as: 'div', delay: 0, threshold: 0.12, once: true, variant: 'up' })
const root = ref<HTMLElement | null>(null)
const shown = ref(false)
let observer: IntersectionObserver | undefined

const variantClass: Record<'up' | 'left' | 'scale', string> = { up: 'fx-in', left: 'fx-in-left', scale: 'fx-in-scale' }

onMounted(() => {
  const element = root.value
  const reduced = getMotionIntensity() === 'off'
  if (!element || reduced || typeof IntersectionObserver === 'undefined') { shown.value = true; return }
  observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue
      shown.value = true
      if (props.once) observer?.disconnect()
    }
  }, { threshold: props.threshold, rootMargin: '0px 0px -8% 0px' })
  observer.observe(element)
})
onBeforeUnmount(() => { observer?.disconnect(); observer = undefined })
</script>

<template>
  <component :is="as" ref="root" class="fx-pending" :class="shown ? variantClass[variant] : ''" :style="shown ? { '--fx-delay': delay + 'ms' } : undefined">
    <slot />
  </component>
</template>
