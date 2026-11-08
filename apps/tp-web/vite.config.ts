import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// tp 区前端：独立部署、独立域名。
// API 前缀写死为 /api/tp —— 跨域访问只能在后端 coordination 完成，前端不得直连别的区。
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5180,
    proxy: {
      '/api/tp': {
        target: process.env.TPAA_TP_UPSTREAM ?? 'http://127.0.0.1:8120',
        changeOrigin: true,
        rewrite: (path) => {
          if (path.startsWith('/api/tp/local-demo/')) {
            return path.replace('/api/tp/local-demo/', '/local-demo/')
          }
          if (path.startsWith('/api/tp/v1/reviews/')) {
            return path.replace('/api/tp/v1/reviews/', '/review/v1/reviews/')
          }
          if (path.startsWith('/api/tp/v1/phc/')) {
            return path.replace('/api/tp/v1/phc/', '/phc/v1/phc/')
          }
          if (path.startsWith('/api/tp/v1/cases')) {
            return path.replace('/api/tp/v1/cases', '/supervision/v1/cases')
          }
          if (path.startsWith('/api/tp/v1/targets')) {
            return path.replace('/api/tp/v1/targets', '/supervision/v1/targets')
          }
          return path.replace('/api/tp/', '/tp/')
        },
      },
    },
  },
})
