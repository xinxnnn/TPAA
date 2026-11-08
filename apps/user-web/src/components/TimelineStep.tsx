import { useState } from 'react'
import type { ReactNode } from 'react'
import type { TimelineEvent } from '../types'
import { ArtifactBox } from './ArtifactBox'

type Props = {
  event: TimelineEvent | undefined
  applicationId: string
  decryptedPreview?: Record<string, unknown>
  title: string
  code: string
  index: number
  active: boolean
  action?: { label: string; onClick: () => void; disabled: boolean }
  children?: ReactNode
  error?: string
}

const statusText: Record<string, string> = {
  pending: '待审核', approved: '已通过', rejected: '已拒绝', complete: '已完成',
  accepted_by_tp: 'TP 已受理', issued_to_user_executor: '已签发', user_accepted: '已接受',
  verified_by_user_executor: '已核验', wallet_accepted: '已接受',
  user_confirmed: '已确认', failed: '失败',
}

export function TimelineStep({ event, applicationId, decryptedPreview, title, code, index,
  active, action, children, error }: Props) {
  const [expanded, setExpanded] = useState(false)
  return <li className={`timeline-step ${event ? 'has-event' : ''} ${active ? 'is-active' : ''}`}>
    <div className="step-marker" aria-hidden="true">{event && event.status !== 'pending' ? '✓' : String(index + 1).padStart(2, '0')}</div>
    <div className="step-body">
      <div className="step-heading"><div><span className="step-code">{code}</span><h3>{title}</h3></div><span className={`status-pill ${event?.status ?? 'waiting'}`}>{event ? statusText[event.status] ?? event.status : '未开始'}</span></div>
      {event?.at && <time className="step-time">{event.at}</time>}
      <div className="step-actions">
        {action && <button type="button" className="primary-button" disabled={action.disabled} onClick={action.onClick}>{action.label}</button>}
        {event?.artifacts && <button type="button" className="detail-button" aria-expanded={expanded} onClick={() => setExpanded(current => !current)}>{expanded ? '收起详情' : '查看详情'}</button>}
      </div>
      {children}
      {error && <p className="step-error" role="alert">{error}</p>}
      {expanded && event && <ArtifactBox event={event} applicationId={applicationId}
        decryptedPreview={decryptedPreview} />}
    </div>
  </li>
}
