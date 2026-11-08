import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const modules = [
  { id: 'summarize', title: '内容摘要', detail: '将长文本压缩成可审阅的要点', tone: 'blue' },
  { id: 'translate', title: '多语言翻译', detail: '支持跨语言的内容转换', tone: 'orange' },
  { id: 'search', title: '知识检索', detail: '从授权知识库中定位相关资料', tone: 'green' },
]

export default function AgentPage() {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<string[]>(['summarize', 'translate'])
  const [stage, setStage] = useState<'choose' | 'review' | 'done'>('choose')
  const [message, setMessage] = useState('')
  const selectedModules = useMemo(() => modules.filter((item) => selected.includes(item.id)), [selected])

  function toggle(id: string) {
    setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  }

  function prepare() {
    if (!selected.length) {
      setMessage('至少选择一项能力。')
      return
    }
    setMessage('')
    setStage('review')
  }

  function confirm() {
    try {
      sessionStorage.setItem('tpaa-demo-credential', JSON.stringify({
        did: 'did:wba:demo-cscid:tp.example:ap.example',
        pa: selectedModules.map((item) => item.title),
        phc: { profile: 'tpaa_v1', version: 3, state: '演示凭证' },
      }))
    } catch {
      // The success view remains usable when browser storage is unavailable.
    }
    setStage('done')
    setMessage('配置已确认，演示环境已生成待签发的 PHC 流程记录。')
  }

  return (
    <section className="flow-page agent-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">AGENT FACTORY / STEP {stage === 'choose' ? '01' : stage === 'review' ? '02' : '03'}</div>
          <h1>{stage === 'choose' ? '选择智能体能力' : stage === 'review' ? '确认这份配置' : '申请已提交'}</h1>
          <p className="lede">{stage === 'choose' ? '每项能力都会进入智能体的配置承诺。你可以在签发前重新检查。' : stage === 'review' ? '确认后，配置将进入签发流程。演示版本不会上传真实身份材料。' : '下一步可以查看当前凭证和智能体状态。'}</p>
        </div>
        <div className="step-counter"><strong>{stage === 'choose' ? '1' : stage === 'review' ? '2' : '3'}</strong><span>/ 3</span></div>
      </div>

      {stage === 'choose' && <div className="module-list">
        {modules.map((item) => {
          const active = selected.includes(item.id)
          return <button className={`module-row ${active ? 'active' : ''}`} key={item.id} onClick={() => toggle(item.id)} type="button">
            <span className={`module-icon ${item.tone}`}>{item.id === 'summarize' ? 'S' : item.id === 'translate' ? '文' : '⌕'}</span>
            <span className="module-copy"><strong>{item.title}</strong><small>{item.detail}</small></span>
            <span className={`check ${active ? 'checked' : ''}`} aria-hidden="true">{active ? '✓' : ''}</span>
          </button>
        })}
      </div>}

      {stage === 'review' && <div className="review-panel">
        <div className="review-label">SELECTED CAPABILITIES</div>
        {selectedModules.map((item) => <div className="review-line" key={item.id}><span>{item.title}</span><b>Included</b></div>)}
        <div className="review-divider" />
        <div className="review-line"><span>配置摘要</span><code>{selected.length} modules / demo-v1</code></div>
        <div className="review-line"><span>用户确认</span><b className="pending">Required</b></div>
      </div>}

      {stage === 'done' && <div className="success-panel"><span className="success-icon">✓</span><div><strong>已进入签发队列</strong><p>你确认的配置已冻结，PHC 和 PA 将按同一份配置承诺生成。</p></div></div>}

      {message && <div className="inline-message">{message}</div>}
      {stage === 'choose' && <button className="primary-action" onClick={prepare} type="button">检查配置 <span aria-hidden="true">→</span></button>}
      {stage === 'review' && <div className="action-row"><button className="secondary-action" onClick={() => setStage('choose')} type="button">返回调整</button><button className="primary-action compact" onClick={confirm} type="button">确认并提交 <span aria-hidden="true">→</span></button></div>}
      {stage === 'done' && <div className="action-row"><button className="secondary-action" onClick={() => navigate('/phc')} type="button">查看 PHC</button><button className="primary-action compact" onClick={() => navigate('/vault')} type="button">打开我的智能体 <span aria-hidden="true">→</span></button></div>}
    </section>
  )
}
