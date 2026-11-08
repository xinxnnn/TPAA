import { useEffect, useState } from 'react'

const stages = [
  { id: 'G1', title: '身份申请', artifacts: 'CR 密文、requestId、AF commitment' },
  { id: 'G2', title: 'TP 受理与审核', artifacts: 'CR digest、TP 审核结论、审批签名证据' },
  { id: 'G3', title: 'PHC 初始签发', artifacts: 'PHC、TPAC、RR 密文' },
  { id: 'G4', title: '用户端接受 PHC', artifacts: 'PHC 签名校验、TPAC 绑定校验' },
  { id: 'D1–D4', title: '选择模块并构建', artifacts: 'CMM、PACI、CMI、PAR 密文' },
  { id: 'D5', title: '用户端核验能力配置', artifacts: '有序模块摘要、CMI 复算结果、DIDGR' },
  { id: 'D6', title: 'DID 与最终 PHC', artifacts: 'DID、PHC digest、TP 最终化声明' },
  { id: 'PUB', title: '发布构建', artifacts: 'buildDigest、Manifest、发布记录' },
] as const

type Event = { stage: string; status: string; at?: string; artifacts?: Record<string, unknown> }
type Timeline = { applicationId: string; state: string; events: Event[] }

export default function PhcPage() {
  const [applicationId, setApplicationId] = useState(() => {
    try { return new URLSearchParams(window.location.search).get('applicationId') ?? '' } catch { return '' }
  })
  const [timeline, setTimeline] = useState<Timeline | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function refresh() {
    if (!applicationId.trim()) return
    setLoading(true)
    setError('')
    try {
      const response = await fetch(`/api/user/v1/applications/${encodeURIComponent(applicationId.trim())}/timeline`)
      const body = await response.json()
      if (!response.ok) throw new Error(body.message ?? body.detail ?? `请求失败 (${response.status})`)
      setTimeline(body as Timeline)
    } catch (e) {
      setError(e instanceof Error ? e.message : '无法读取申请进度')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (applicationId) void refresh()
  }, [])

  const events = new Map((timeline?.events ?? []).map((event) => [event.stage, event]))
  return (
    <section className="flow-page">
      <div className="eyebrow">TPAA V1 / CREDENTIAL WORKFLOW</div>
      <h1>申领进度与产物</h1>
      <p className="lede">按申请编号查询 G1–D6 与发布阶段。页面只展示摘要和状态，不显示 PII、BI、H(ID)、陷门随机数或私钥。</p>
      <form className="review-panel" onSubmit={(event) => { event.preventDefault(); void refresh() }}>
        <label className="review-label" htmlFor="application-id">申请编号</label>
        <div className="action-row">
          <input id="application-id" value={applicationId} onChange={(event) => setApplicationId(event.target.value)} placeholder="app-…" />
          <button className="primary-action compact" disabled={loading || !applicationId.trim()} type="submit">{loading ? '查询中…' : '查询进度'}</button>
        </div>
      </form>
      {error && <div className="inline-message" role="alert">{error}</div>}
      {timeline && <div className="workflow-timeline" aria-label="协议流程进度">
        {stages.map((stage) => {
          const event = events.get(stage.id)
          const done = Boolean(event)
          return <article className={`workflow-step ${done ? 'complete' : ''}`} key={stage.id}>
            <div className="workflow-marker">{done ? '✓' : stage.id}</div>
            <div className="workflow-content">
              <div className="workflow-head"><strong>{stage.title}</strong><span>{event?.status ?? '待开始'}</span></div>
              <p>{stage.artifacts}</p>
              {event?.at && <small>{event.at}</small>}
              {event?.artifacts && <dl>{Object.entries(event.artifacts).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd></div>)}</dl>}
            </div>
          </article>
        })}
      </div>}
    </section>
  )
}
