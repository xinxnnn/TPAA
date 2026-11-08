import { useEffect, useState } from 'react'

const DEMO_AGENT = {
  did: 'did:wba:demo-cscid:tp.example:ap.example',
  pa: ['内容摘要', '多语言翻译'],
  phc: { profile: 'tpaa_v1', version: 3, state: '演示凭证' },
}

export default function VaultPage() {
  const [credential, setCredential] = useState<typeof DEMO_AGENT | null>(null)

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem('tpaa-demo-credential')
      setCredential(raw ? JSON.parse(raw) as typeof DEMO_AGENT : DEMO_AGENT)
    } catch {
      setCredential(DEMO_AGENT)
    }
  }, [])

  return (
    <section className="flow-page">
      <div className="eyebrow">MY AGENTS / CREDENTIAL VAULT</div>
      <h1>我的智能体</h1>
      <p className="lede">已签发的 DID、凭证和能力清单。</p>
      {credential ? <div className="credential-panel">
        <div className="review-label">DECENTRALIZED IDENTIFIER</div>
        <code className="did-value">{credential.did}</code>
        <div className="review-divider" />
        <div className="review-label">CAPABILITIES</div>
        {credential.pa.map((item) => <div className="review-line" key={item}><span>{item}</span><b>演示凭证</b></div>)}
        <div className="review-divider" />
        <div className="review-line"><span>PHC profile</span><code>{credential.phc.profile} / v{credential.phc.version}</code></div>
      </div> : <div className="empty-state"><span className="empty-mark">—</span><strong>还没有已签发的智能体</strong><p>完成一次申领后，DID 和凭证会显示在这里。</p></div>}
    </section>
  )
}
