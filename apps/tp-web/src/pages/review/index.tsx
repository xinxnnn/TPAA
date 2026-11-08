import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ApiError, decideReview, getReviewDetail, getReviewQueue } from '../../services/review-client'
import type { ReviewItem } from '../../services/review-client'

type Decision = 'approve' | 'reject'
type Filter = 'pending' | 'all'

function statusLabel(state: string) {
  if (state === 'approved') return '已通过'
  if (state === 'rejected') return '已驳回'
  return '待审核'
}

function readableError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'TP reviewer 会话无效或已过期，请重新登录。'
    if (error.status === 403) {
      return error.message.startsWith('需要角色 ')
        ? `当前账号无 reviewer 权限：${error.message}`
        : `审核队列读取失败：${error.message}`
    }
    if (error.status === 404) return `申请记录不存在：${error.message}`
    if (error.status === 409) return `该申请已被判定，队列正在刷新：${error.message}`
    return `审核服务返回 ${error.status}：${error.message}`
  }
  return error instanceof Error ? error.message : '审核服务暂不可用。'
}

export default function ReviewPage() {
  const [items, setItems] = useState<ReviewItem[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [selected, setSelected] = useState<ReviewItem | null>(null)
  const [filter, setFilter] = useState<Filter>('pending')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')
  const [error, setError] = useState('')
  const refreshInFlight = useRef(false)

  const visible = useMemo(() => filter === 'all' ? items : items.filter(item => item.state === 'pending_review' || item.state === 'open'), [items, filter])

  const refresh = useCallback(async (preferredId?: string, silent = false) => {
    if (refreshInFlight.current) return
    refreshInFlight.current = true
    if (!silent) setLoading(true)
    setError('')
    try {
      const queue = await getReviewQueue()
      setItems(queue.items)
      const target = preferredId ?? selectedId
      const targetItem = queue.items.find(item => item.applicationId === target)
      const nextItem = targetItem ?? queue.items[0]
      const nextId = nextItem?.applicationId ?? ''
      setSelectedId(nextId)
      if (!nextItem) {
        setSelected(null)
      } else {
        const detailChanged = !selected
          || selected.applicationId !== nextId
          || selected.state !== nextItem.state
          || JSON.stringify(selected.review) !== JSON.stringify(nextItem.review)
        if (detailChanged) setSelected(await getReviewDetail(nextId))
      }
    } catch (reason) {
      setError(readableError(reason))
      setSelected(null)
    } finally {
      refreshInFlight.current = false
      if (!silent) setLoading(false)
    }
  }, [selected, selectedId])

  useEffect(() => { void refresh() }, [])
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible' && !busy) void refresh(undefined, true)
    }, 3000)
    return () => window.clearInterval(timer)
  }, [busy, refresh])

  async function select(applicationId: string) {
    setSelectedId(applicationId)
    setToast('')
    setError('')
    try { setSelected(await getReviewDetail(applicationId)) }
    catch (reason) { setError(readableError(reason)); setSelected(null) }
  }

  async function decide(decision: Decision) {
    if (!selected || busy) return
    if (decision === 'reject' && !note.trim()) {
      setError('驳回前请填写处理意见。')
      return
    }
    setBusy(true)
    setError('')
    setToast('')
    try {
      await decideReview(selected.applicationId, decision, note.trim())
      setNote('')
      setToast(decision === 'approve' ? 'TP 审核完成：申请已批准。' : 'TP 审核完成：申请已驳回。')
      await refresh(selected.applicationId)
    } catch (reason) {
      const message = readableError(reason)
      setError(message)
      if (reason instanceof ApiError && reason.status === 409) await refresh(selected.applicationId)
    } finally { setBusy(false) }
  }

  return <section className="tp-page">
    <div className="tp-heading">
      <div><div className="eyebrow">TRUST PROVIDER / REVIEW DESK</div><h1>申领审核</h1><p className="lede">由登录令牌标识的单名 TP reviewer 判定。申请队列每 3 秒刷新；队列只返回掩码身份与 BI 字段名，不返回原始材料。</p></div>
      <button className="detail-button" disabled={loading || busy} onClick={() => void refresh()}>刷新队列</button>
    </div>
    <div className="review-toolbar"><div className="tabs"><button className={filter === 'pending' ? 'active' : ''} onClick={() => setFilter('pending')}>待审核 <b>{items.filter(item => item.state === 'pending_review' || item.state === 'open').length}</b></button><button className={filter === 'all' ? 'active' : ''} onClick={() => setFilter('all')}>全部申请</button></div><span className="detail-label">审核员身份由 TP 登录会话确定</span></div>
    {error && <div className="notice-panel" role="alert"><p>{error}</p></div>}
    {toast && <div className="notice-panel success-panel" role="status"><p>{toast}</p></div>}
    <div className="review-layout">
      <div className="queue" aria-label="申请队列">
        {visible.map(item => <button key={item.applicationId} className={`queue-item ${selected?.applicationId === item.applicationId ? 'chosen' : ''}`} onClick={() => void select(item.applicationId)}>
          <span className={`queue-status ${item.state}`} /><span className="queue-main"><strong>{item.applicationId}</strong><small>{item.receivedAt}</small></span><span className={`state-label ${item.state}`}>{statusLabel(item.state)}</span>
        </button>)}
        {loading && <div className="queue-empty">正在读取 TP 审核队列…</div>}
        {!loading && !visible.length && <div className="queue-empty">当前没有符合筛选条件的申请。</div>}
      </div>
      {selected && <article className="application-detail">
        <div className="detail-head"><div><div className="eyebrow">APPLICATION / {selected.applicationId}</div><h2>{selected.applicationId}</h2></div><span className={`state-pill ${selected.state}`}>{statusLabel(selected.state)}</span></div>
        <div className="detail-grid">
          <div className="detail-block"><span className="detail-label">提交时间</span><strong>{selected.receivedAt}</strong></div>
          <div className="detail-block"><span className="detail-label">CR 摘要</span><code>{selected.crDigest}</code></div>
          {Object.entries(selected.pii).map(([key, value]) => <div className="detail-block" key={key}><span className="detail-label">{key}（脱敏）</span><strong>{value}</strong></div>)}
        </div>
        <div className="detail-section"><div className="section-title">身份验证材料 <span>BI 项目名可见；照片仅本地测试详情可预览</span></div><div className="chip-row">{selected.biFields.map(field => <span className="material-chip" key={field}><i />{field}</span>)}</div></div>
        {selected.demoFacePhotoPreview && <div className="detail-section">
          <div className="section-title">合成测试照片 <span>仅本地 test-adapter reviewer 详情可见</span></div>
          <img className="demo-photo-preview" src={selected.demoFacePhotoPreview} alt="用户提交的合成测试照片" />
        </div>}
        <div className="detail-section"><div className="section-title">审核判定 <span>{selected.review?.decisions.length ? '已完成' : '单名审核'}</span></div>
          {selected.review?.decisions.map((entry, i) => <div className="audit-line" key={`${entry.reviewer}-${i}`}><span>{entry.reviewer}</span><b>{entry.decision === 'approve' ? '批准' : '驳回'}</b><time>{entry.at}</time></div>)}
        </div>
        {(!selected.review || selected.review.state === 'open') && <div className="decision-area"><label htmlFor="review-note">审核意见 <span>驳回时必填</span></label><textarea id="review-note" value={note} onChange={event => setNote(event.target.value)} placeholder="填写审核依据；驳回时说明原因" rows={3} disabled={busy} /><div className="decision-actions"><button className="reject-button" disabled={busy || !note.trim()} onClick={() => void decide('reject')}>驳回申请</button><button className="approve-button" disabled={busy} onClick={() => void decide('approve')}>{busy ? '提交中…' : '批准并签署'}</button></div></div>}
      </article>}
    </div>
  </section>
}
