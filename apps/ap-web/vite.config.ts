import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ap 区前端：独立部署、独立域名。
// API 前缀写死为 /api/ap —— 跨域访问只能在后端 coordination 完成，前端不得直连别的区。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
    proxy: {
      '/api/ap': {
        target: process.env.TPAA_AP_UPSTREAM ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
