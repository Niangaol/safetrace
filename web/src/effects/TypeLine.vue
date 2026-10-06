<script setup lang="ts">
/** 打字机：只用于静态标题/说明，不用于回答正文（正文必须整段可见以便核对引用）。 */
import { onBeforeUnmount, ref, watch } from 'vue'
import { getMotionIntensity } from './motion-prefs'

const props = withDefaults(defineProps<{ text: string; speed?: number; startDelay?: number; cursor?: boolean }>(), { speed: 42, startDelay: 220, cursor: true })
const shown = ref('')
let timer: ReturnType<typeof setInterval> | undefined
let startTimer: ReturnType<typeof setTimeout> | undefined

function stop() { if (timer !== undefined) { globalThis.clearInterval(timer); timer = undefined } if (startTimer !== undefined) { globalThis.clearTimeout(startTimer); startTimer = undefined } }
function play() {
  stop()
  const full = props.text
  if (getMotionIntensity() === 'off' || props.speed <= 0) { shown.value = full; return }
  shown.value = ''
  startTimer = globalThis.setTimeout(() => {
    let index = 0
    timer = globalThis.setInterval(() => {
      index += 1
      shown.value = full.slice(0, index)
      if (index >= full.length) stop()
    }, props.speed)
  }, props.startDelay)
}
watch(() => props.text, play, { immediate: true })
onBeforeUnmount(stop)
</script>

<template>
  <span :class="cursor ? 'fx-type-cursor' : ''">{{ shown || '​' }}</span>
</template>
