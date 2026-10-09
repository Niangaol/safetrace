import { createRouter, createWebHistory } from 'vue-router'

import DashboardView from './views/DashboardView.vue'
import DetailView from './views/DetailView.vue'
import IntelView from './views/IntelView.vue'
import IngestDiagnosticsView from './views/IngestDiagnosticsView.vue'
import QaView from './views/QaView.vue'
import SettingsView from './views/SettingsView.vue'
import AssetsView from './views/AssetsView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/dashboard' },
    { path: '/dashboard', component: DashboardView },
    { path: '/intel', component: IntelView },
    { path: '/intel/:id', component: DetailView, props: true },
    { path: '/ingest-diagnostics', component: IngestDiagnosticsView },
    { path: '/assets', component: AssetsView },
    { path: '/qa', component: QaView },
    { path: '/settings', component: SettingsView },
  ],
})
