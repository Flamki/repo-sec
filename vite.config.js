import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 8080,
    allowedHosts: true,
    proxy: {
      '/scan': 'http://localhost:8000',
      '/scans': 'http://localhost:8000',
      '/leaderboard': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/skill.json': 'http://localhost:8000',
      '/docs': 'http://localhost:8000',
      '/redoc': 'http://localhost:8000',
      '/openapi.json': 'http://localhost:8000',
    }
  },
  preview: {
    host: '0.0.0.0',
    port: 8080,
    allowedHosts: true
  }
})
