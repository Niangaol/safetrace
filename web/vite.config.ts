import os from 'node:os'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// vite 6 有 host 头校验：用机器名或本机 IP 打开会被 403 "Blocked request"，
// 这里显式放行本机所有网卡地址，否则除 127.0.0.1/localhost 外的入口全挂
const localHosts = Object.values(os.networkInterfaces())
  .flat()
  .filter((i): i is os.NetworkInterfaceInfo => !!i && !i.internal && i.family === 'IPv4')
  .map((i) => i.address)

// 开发态把 /api 代理到 FastAPI，避免前端单独配 CORS 与 token
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    // DSH guarded edits create short-lived atomic-write files; do not watch these intermediates.
    watch: { ignored: ['**/*.tmpdir/**', '**/*.tmpdir', '**/*.tmp'] },
    allowedHosts: ['localhost', '127.0.0.1', ...localHosts, os.hostname()],
    proxy: {
      // 用 127.0.0.1 而不是 localhost：后者在部分 Windows 环境会解析到 ::1，
      // 而 uvicorn 只监听 IPv4，代理就会 ECONNREFUSED（表现为前端 fetch 全挂）
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/health': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  build: { outDir: 'dist' },
})
