import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { AppShell } from '../../shared/ui'
import { ApiError, isSessionCurrent, post } from './services/api-client'
import ReviewPage from './pages/review'
import PhcPage from './pages/phc'
import DidPage from './pages/did'
import SupervisionPage from './pages/supervision'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'

type DemoSession = { token: string; subject: string; role: string; expires: string }
const nav = [{ to: '/review', label: '申领审核', icon: '▤' }, { to: '/phc', label: 'PHC 签发', icon: '◇' }, { to: '/did', label: 'DID 目录', icon: '⌘' }, { to: '/supervision', label: '监管案件', icon: '!' }]
const SESSION_KEY = 'tpaa.tp.demo-reviewer-session'

function Console() {
  const location = useLocation()
  const [session, setSession] = useState<DemoSession | null>(() => {
    try {
      const value = sessionStorage.getItem(SESSION_KEY)
      if (!value) return null
      const parsed = JSON.parse(value) as DemoSession
      return isSessionCurrent(parsed.expires) ? parsed : null
    } catch {
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }
  })
  const [loginBusy, setLoginBusy] = useState(false)
  const [loginError, setLoginError] = useState('')

  async function startDemoReviewerSession() {
    setLoginBusy(true)
    setLoginError('')
    try {
      const value = await post<{ profile: string; subject: string; role: string; token: string; expires: string }>(
        '/api/tp/local-demo/reviewer-session', {},
      )
      if (value.profile !== 'test-adapter' || value.subject !== 'reviewer-a'
          || value.role !== 'reviewer' || !value.token
          || !isSessionCurrent(value.expires)) {
        throw new Error('TP 未返回有效的本地 reviewer 测试会话')
      }
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(value))
      setSession(value)
    } catch (reason) {
      setLoginError(reason instanceof ApiError
        ? `无法开始本地审核演示：${reason.message}`
        : reason instanceof Error ? reason.message : '本地审核服务不可用')
    } finally {
      setLoginBusy(false)
    }
  }

  function endDemoReviewerSession() {
    sessionStorage.removeItem(SESSION_KEY)
    setSession(null)
  }

  async function switchDemoSupervisor(staffId: string) {
    const value = await post<DemoSession & { profile: string }>(
      '/api/tp/local-demo/supervisor-session', { staffId },
    )
    if (value.profile !== 'test-adapter' || value.subject !== staffId
        || value.role !== 'supervisor' || !value.token
        || !isSessionCurrent(value.expires)) {
      throw new Error('TP 未返回有效的本地监管员测试会话')
    }
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(value))
    setSession(value)
  }

  if (!session) {
    return <section className="review-demo-gate">
      <div className="eyebrow">LOCAL TEST ADAPTER / TP REVIEWER</div>
      <h1>TP 申请审核演示</h1>
      <p>仅限本机 test-adapter。服务端使用本地测试 STAFF 密钥签署一次性 TP challenge；浏览器只接收短期 reviewer 令牌，不接触私钥。此流程不代表真实人员认证。</p>
      {loginError && <p className="review-demo-error" role="alert">{loginError}</p>}
      <button className="approve-button" disabled={loginBusy} onClick={() => void startDemoReviewerSession()}>
        {loginBusy ? '正在建立签名会话…' : '开始本地审核演示'}
      </button>
    </section>
  }

  return <div className="shell tp-shell">
    <aside className="sidebar"><div className="brand"><span className="brand-symbol">T</span><span><strong>TPAA</strong><small>Trust Provider</small></span></div><div><div className="nav-label">CONTROL DESK</div><nav className="nav-list">{nav.map((item) => <NavLink className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} to={item.to} key={item.to}><span className="nav-icon">{item.icon}</span>{item.label}</NavLink>)}</nav></div><div className="sidebar-bottom">TP 域控制台<br />单名审核 · 凭证留痕</div></aside>
    <div className="main-area"><header className="topbar"><div className="breadcrumb">TP 区 <span>/</span> <b>{nav.find((x) => x.to === location.pathname)?.label ?? '控制台'}</b></div><div className="profile"><span className="profile-mark">TP</span>{session.subject} · test-adapter <button className="session-end-button" onClick={endDemoReviewerSession}>结束演示</button></div></header><main className="content"><div className="review-demo-banner">本地测试会话 · 监管操作使用独立的模拟监管员密钥；不代表真实人员认证</div><Routes><Route path="/review" element={<ReviewPage />} /><Route path="/phc" element={<PhcPage />} /><Route path="/did" element={<DidPage />} /><Route path="/supervision" element={<SupervisionPage session={session} onSwitchSupervisor={switchDemoSupervisor} />} /><Route path="*" element={<Navigate to="/review" replace />} /></Routes></main></div>
  </div>
}

export default function App() { return <BrowserRouter><AppShell title="" zone="tp"><Console /></AppShell></BrowserRouter> }
