import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import { router } from './router'
import './style.css'
import './effects/effects.css'
import { applyMotionIntensity, getMotionIntensity } from './effects/motion-prefs'

// 首帧前确定动效开关：系统偏好减少动效时默认关闭，用户显式选择后尊重用户。
applyMotionIntensity(getMotionIntensity())

createApp(App).use(createPinia()).use(router).mount('#app')
