import { createRouter, createWebHistory } from 'vue-router'

import HomeView from './views/HomeView.vue'
import ConfigView from './views/ConfigView.vue'
import DashboardView from './views/DashboardView.vue'
import DetailView from './views/DetailView.vue'
import IntelView from './views/IntelView.vue'
import QaView from './views/QaView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: HomeView },
    { path: '/dashboard', component: DashboardView },
    { path: '/intel', component: IntelView },
    { path: '/intel/:id', component: DetailView, props: true },
    { path: '/qa', component: QaView },
    { path: '/config', component: ConfigView },
  ],
})
