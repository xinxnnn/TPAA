import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../../services/api-client'
import { getPhcReviewerQueue } from '../../services/phc-client'
import type { PhcQueueItem } from '../../services/phc-client'

function stateLabel(item: PhcQueueItem) {
  if (item.finalized) return 'D6 已完成'
  if (item.issued) return 'PHC 已签发，等待用户完成 G4 / D1-D6'
  if (item.reviewState === 'approved') return '审核通过，等待用户领取'
  if (item.reviewState === 'rejected') return '申请已驳回'
  return '等待审核'
}

function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'TP reviewer 会话无效或已过期，请重新开始本地审核演示。'
    if (error.status === 403) {
      return error.message.startsWith('需要角色 ')
        ? `当前账号无 reviewer 权限：${error.message}`
        : `PHC 状态读取失败：${error.message}`
    }
    return `PHC 服务返回 ${error.status}：${error.message}`
  }
  return error instanceof Error ? error.message : 'PHC 服务暂不可用。'
}

export default function PhcPage() {
  const [items, setItems] = useState<PhcQueueItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const result = await getPhcReviewerQueue()
      setItems(result.items)
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  return <section className="tp-page">
    <div className="tp-heading">
      <div>
        <div className="eyebrow">TRUST PROVIDER / PHC SERVICE</div>
        <h1>PHC 签发进度</h1>
        <p className="lede">展示 review-service 与 phc-service 的真实状态。PHC 加密凭证由申请人流程领取，TP 审核台不代替用户签发或接收凭证。</p>
      </div>
      <button className="detail-button" disabled={loading} onClick={() => void refresh()}>刷新状态</button>
    </div>
    {error && <div className="notice-panel" role="alert"><p>{error}</p></div>}
    <div className="queue phc-queue" aria-label="PHC 申请进度">
      {items.map(item => <article className="phc-queue-item" key={item.applicationId}>
        <div className="phc-queue-heading">
          <div><span className="detail-label">申请编号</span><strong>{item.applicationId}</strong></div>
          <span className={`state-pill ${item.finalized || item.issued || item.reviewState === 'approved' ? 'approved' : ''}`}>{stateLabel(item)}</span>
        </div>
        <div className="phc-queue-meta">
          <span>G1 受理：{item.receivedAt}</span>
          <span>PHC 版本：{item.phcVersion ?? '尚未签发'}</span>
        </div>
        {item.phcDigest && <div className="phc-digest"><span className="detail-label">PHC 摘要</span><code>{item.phcDigest}</code></div>}
      </article>)}
      {loading && <div className="queue-empty">正在读取签发状态…</div>}
      {!loading && !error && !items.length && <div className="queue-empty">当前没有申请记录。请先从 User Web 提交合成演示申请。</div>}
    </div>
    <div className="notice-panel phc-boundary-note"><strong>职责边界</strong><p>reviewer 队列只读取脱敏身份与公开的签发状态；加密 RR / FINAL、H(ID)、ECID 和签名私钥不会返回此页面。通过审核后，用户需在 User Web 主动领取 PHC 并完成后续 D1–D6。</p></div>
  </section>
}
