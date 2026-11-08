import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// user 区前端：独立部署、独立域名。
// API 前缀写死为 /api/user —— 跨域访问只能在后端 coordination 完成，前端不得直连别的区。
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api/user': {
        target: process.env.TPAA_USER_UPSTREAM ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
