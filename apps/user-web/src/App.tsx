import { useEffect, useState } from 'react'
import { BrandBar } from './components/BrandBar'
import { IdentityForm } from './components/IdentityForm'
import { WorkflowTimeline } from './components/WorkflowTimeline'
import { ApiError, createApplication, getInitialization, getLocalSession, getTimeline, listApplications, startLocalSession, transition } from './services/flow-client'
import type { ApplicationSummary, Initialization, Selection, Timeline } from './types'
import type { LocalSessionStatus } from './services/flow-client'

function describeError(error: unknown, action?: string): string {
    if (error instanceof ApiError) {
      if (error.status === 401) return '本地用户会话已过期。刷新页面以重新建立 test-adapter 会话后再试。'
      if (error.status === 403) return `无权执行该步骤：${error.message}`
      if (error.status === 404) return `申请或上游记录不存在：${error.message}`
      if (error.status === 409) return `流程状态冲突：${error.message}`
      if (error.status === 500 && action === 'create') return '申请提交未得到完成回执，暂时无法确认 TP 是否已受理。请先检查 TP 待审核队列和 Portal 日志，确认前不要重复提交。'
      if (error.status === 500) return 'Portal 服务内部错误。请检查 Portal 启动终端中的配置和上游服务状态。'
      return `服务返回 ${error.status}：${error.message}`
    }
  if (action === 'begin-agent') return 'AP 服务未启动或不可达，无法拉取能力目录；请检查 AP 服务后重试。'
  return error instanceof Error ? error.message : '服务不可用，请稍后重试。'
}

export default function App() {
  const [initialization, setInitialization] = useState<Initialization | null>(null)
  const [localSession, setLocalSession] = useState<LocalSessionStatus | null>(null)
  const [applications, setApplications] = useState<ApplicationSummary[]>([])
  const [timeline, setTimeline] = useState<Timeline | null>(null)
  const [selection, setSelection] = useState<Selection[]>([])
  const [busy, setBusy] = useState(false)
  const [pendingAction, setPendingAction] = useState<string>()
  const [error, setError] = useState('')
  const [bootError, setBootError] = useState('')

  async function loadApplications() {
    const response = await listApplications()
    setApplications(response.items)
    return response.items
  }

  async function loadWorkspace() {
    const [init, listed] = await Promise.all([getInitialization(), listApplications()])
    setInitialization(init)
    setApplications(listed.items)
  }

  useEffect(() => {
    let active = true
    getLocalSession().then(async status => {
      if (!active) return
      if (status.enabled && !status.authenticated) {
        const started = await startLocalSession()
        if (!active) return
        setLocalSession({ ...started, authenticated: true })
      } else {
        setLocalSession(status)
      }
      await loadWorkspace()
    }).catch(reason => {
      if (active) {
        setBootError(describeError(reason))
        setLocalSession(current => current?.enabled
          ? { ...current, authenticated: false }
          : current)
      }
    })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!timeline) return
    let active = true
    const applicationId = timeline.applicationId
    const timer = window.setInterval(() => {
      if (document.visibilityState !== 'visible' || busy) return
      getTimeline(applicationId)
        .then(updated => {
          if (active) setTimeline(updated)
        })
        .catch(reason => {
          if (active) setError(describeError(reason))
        })
    }, 4000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [timeline?.applicationId, busy])

  async function chooseApplication(id: string) {
    setError('')
    try { setTimeline(await getTimeline(id)); setSelection([]) }
    catch (reason) { setBootError(describeError(reason)) }
  }

  async function refresh() {
    if (!timeline) return
    try { setTimeline(await getTimeline(timeline.applicationId)); await loadApplications(); setError('') }
    catch (reason) { setError(describeError(reason)) }
  }

  async function create(body: { pii: Record<string, string>; bi: Record<string, string> }): Promise<boolean> {
    setBusy(true); setError('')
    try { const created = await createApplication(body); setTimeline(created); setSelection([]); await loadApplications(); return true }
    catch (reason) { setError(describeError(reason, 'create')); return false }
    finally { setBusy(false) }
  }

  async function act(action: string, body: Record<string, unknown> = {}) {
    if (!timeline || busy) return
    const id = timeline.applicationId
    setBusy(true); setPendingAction(action); setError('')
    try {
      const updated = await transition(id, action, body)
      setTimeline(updated)
      await loadApplications()
    } catch (reason) { setError(describeError(reason, action)) }
    finally { setBusy(false); setPendingAction(undefined) }
  }

  return <div className="app-shell">
    <BrandBar initialization={initialization} testAdapterSessionActive={localSession?.enabled && localSession.authenticated} />
    <main className="content-wrap">
    <div className="page-intro"><div><span className="section-kicker">TPAA V1 · PROTOCOL FLOW</span><h1>身份凭证与能力授权</h1><p>由用户主动提交申请、等待 TP 审批，并逐步执行 G3–D6；页面只自动同步状态，不会生成样例申请或自动推进流程。本轮不包含 Agent 制品或 Runtime。</p></div><div className="profile-note">执行环境：{initialization?.checks.executionProfile ?? '连接中'} · 用户独立控制：{initialization?.checks.userControlledExecution ? '是' : '否'}</div></div>
    {localSession?.enabled && <div className="demo-banner" role="status">本地 test-adapter · 仅使用合成身份和测试照片 · 本地会话只用于开发验证，不代表真实用户认证</div>}
    {bootError && <div className="global-error" role="alert">{bootError}</div>}
    {initialization && <section className="card initialization-card" aria-labelledby="initialization-heading">
      <div className="section-heading"><div><span className="section-kicker">INIT</span><h2 id="initialization-heading">当前协议参数与参与方公钥</h2></div><span className="flow-state">{initialization.paramsId}</span></div>
      <p>以下内容来自本次运行中的 TP、AP、用户执行器及监管 Paillier 公钥，不是独立 demo 重新生成的密钥；只展示公开材料，不包含私钥。</p>
      <details><summary>查看完整初始化参数、自检结果和公钥</summary>
        <pre className="initialization-json">{JSON.stringify(initialization, null, 2)}</pre>
      </details>
    </section>}
    {initialization && <IdentityForm busy={busy} disabled={false} testAdapter={localSession?.enabled === true} onSubmit={create} />}
    {initialization && <div className="application-bar"><div><strong>我的申请</strong><span>申请状态与阶段产物从 Portal 服务读取。</span></div><div className="application-controls"><select aria-label="选择申请" value={timeline?.applicationId ?? ''} onChange={e => void chooseApplication(e.target.value)} disabled={!initialization}><option value="">{applications.length ? '选择申请' : '尚无可用申请'}</option>{applications.map(item => <option key={item.applicationId} value={item.applicationId}>{item.applicationId} · {item.state}</option>)}</select><button type="button" className="detail-button" onClick={() => void refresh()} disabled={!timeline || busy}>刷新状态</button></div></div>}
    {timeline ? <WorkflowTimeline timeline={timeline} busy={busy} pendingAction={pendingAction} selection={selection} onSelection={setSelection} onAction={(action, body) => void act(action, body)} error={error} /> : initialization ? <section className="card empty-flow"><h2>尚未选择申请</h2><p>{applications.length ? '历史申请不会自动载入。请选择一条申请，或提交新身份申请开始一条独立流程。' : '提交身份申请后，G1 回执和后续 PHC 阶段会关联到同一个申请编号。'}</p>{error && <p role="alert" className="step-error">{error}</p>}</section> : <section className="card empty-flow"><h2>流程暂不可用</h2><p>无法连接用户流程服务，请检查 Portal、Executor、TP/AP 组合服务状态。</p></section>}
    <footer className="workbench-footer">流程按真实服务返回的状态推进；表单材料只用于加密 CR 和 PHC 身份绑定验证。当前没有人脸识别，且本地 test-adapter 不代表生产密钥托管。</footer>
    </main>
  </div>
}
