import { useEffect, useMemo, useState } from 'react'
import { ApiError } from '../../services/api-client'
import { getDidDirectory } from '../../services/phc-client'
import type { DidDirectoryItem } from '../../services/phc-client'

function shorten(value: string) {
  return value.length > 52 ? `${value.slice(0, 27)}…${value.slice(-18)}` : value
}

export default function DidPage() {
  const [records, setRecords] = useState<DidDirectoryItem[]>([])
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    getDidDirectory().then(result => {
      if (!active) return
      setRecords(result.items)
      setSelected(current => result.items.some(item => item.did === current)
        ? current : result.items[0]?.did ?? '')
    }).catch(reason => {
      if (!active) return
      if (reason instanceof ApiError) {
        setError(reason.status === 401
          ? 'TP reviewer 会话无效或已过期，请重新开始本地审核演示。'
          : `DID 索引服务返回 ${reason.status}：${reason.message}`)
      } else {
        setError(reason instanceof Error ? reason.message : 'DID 索引服务暂不可用。')
      }
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  const filtered = useMemo(() => records.filter(item =>
    !query || item.did.toLowerCase().includes(query.toLowerCase())
      || item.applicationId.toLowerCase().includes(query.toLowerCase())), [records, query])
  const item = records.find(record => record.did === selected)

  return <section className="tp-page">
    <div className="eyebrow">TRUST PROVIDER / DID DIRECTORY</div>
    <h1>DID 目录</h1>
    <p className="lede">显示实际完成 D6 的 TP 凭证绑定记录。该列表来自 PHC 服务的已完成记录，不代表独立 DID 注册、撤销或子体追溯目录。</p>
    <div className="did-search"><input value={query} onChange={event => setQuery(event.target.value)} placeholder="按 DID 或申请编号检索" /><span>{filtered.length} records</span></div>
    {error && <div className="notice-panel" role="alert"><p>{error}</p></div>}
    <div className="did-layout">
      <div className="queue" aria-label="D6 DID 绑定记录">
        {filtered.map(record => <button key={record.did} className={`queue-item ${record.did === selected ? 'chosen' : ''}`} onClick={() => setSelected(record.did)}>
          <span className="queue-status approved" />
          <span className="queue-main"><strong>{shorten(record.did)}</strong><small>{record.applicationId}</small></span>
          <span className="state-label approved">D6 已绑定</span>
        </button>)}
        {loading && <div className="queue-empty">正在读取 D6 绑定记录…</div>}
        {!loading && !error && !filtered.length && <div className="queue-empty">尚无 D6 完成记录。完成 G1→审核→G3/G4→D1–D6 后，此处会显示真实绑定。</div>}
      </div>
      {item && <article className="application-detail">
        <div className="eyebrow">D6 BINDING / {item.applicationId}</div>
        <h2 className="did-full-value">{item.did}</h2>
        <div className="detail-grid did-detail">
          <div className="detail-block"><span className="detail-label">D6 状态</span><strong>TP 已完成绑定</strong></div>
          <div className="detail-block"><span className="detail-label">PHC 版本</span><strong>v{item.phcVersion}</strong></div>
          <div className="detail-block"><span className="detail-label">PHC 摘要</span><code>{item.phcDigest}</code></div>
        </div>
        <div className="notice-panel"><strong>当前接入边界</strong><p>本地 TP 组合栈查询的是 PHC 服务中已完成 D6 的绑定事实。独立 did-service 注册、父子关系、撤销状态及监管追溯仍未接入此页面，因此不在此伪装显示。</p></div>
      </article>}
    </div>
  </section>
}
