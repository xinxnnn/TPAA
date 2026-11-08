import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ops 区前端：独立部署、独立域名。
// API 前缀写死为 /api/ops —— 跨域访问只能在后端 coordination 完成，前端不得直连别的区。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5176,
    proxy: {
      '/api/ops': {
        target: process.env.TPAA_OPS_UPSTREAM ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
