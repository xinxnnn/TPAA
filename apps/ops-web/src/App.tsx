// TPAA 平台运营台（ops 区）
//
// 边界约束（由 scripts/check_frontend_boundary.py 强制）：
//   1. 只允许访问 /api/ops 前缀的本区后端；不得直连其他区
//   2. 前端不持有任何密钥、不做加解密 —— 密码学动作只在后端 crypto.sdk 内发生
//   3. 派生子智能体必须由用户在本端手动确认（见 pages/subagent/confirm）

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
// 相对路径引用同级 shared（避免 node API；依赖提升到 frontend/ 根后才可解析）
import { AppShell } from '../../shared/ui'

import OverviewPage from './pages/overview'
import ModuleReviewPage from './pages/module-review'
import StatsPage from './pages/stats'
import PermissionsPage from './pages/permissions'

export default function App() {
  return (
    <BrowserRouter>
      <AppShell title="TPAA 平台运营台" zone="ops">
        <Routes>
          <Route path="/" element={<Navigate to="overview" replace />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/module-review" element={<ModuleReviewPage />} />
          <Route path="/stats" element={<StatsPage />} />
          <Route path="/permissions" element={<PermissionsPage />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  )
}
