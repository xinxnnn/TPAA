import { useEffect, useMemo, useState } from 'react'
import {
  approveCase,
  createDemoApproval,
  discloseCase,
  getCases,
  getForensicPackage,
  getRevealedIdentity,
  getTraceTargets,
  rejectCase,
  reportCase,
} from '../../services/supervision-client'
import type {
  ForensicResult,
  RevealedIdentity,
  SupervisionCase,
} from '../../services/supervision-client'

type Props = {
  session: { subject: string; role: string }
  onSwitchSupervisor: (staffId: string) => Promise<void>
}

const supervisorIds = ['supervisor-a', 'supervisor-b'] as const
const stateLabels: Record<SupervisionCase['state'], string> = {
  reported: '待双人立案',
  filed: '已立案',
  investigating: '协查中',
  disclosed: '已揭露',
  sealed: '已封存取证',
  rejected: '不予受理',
  closed: '已关闭',
}

function shortDid(did: string) {
  return did.length > 68 ? `${did.slice(0, 38)}…${did.slice(-20)}` : did
}

export default function SupervisionPage({ session, onSwitchSupervisor }: Props) {
  const [cases, setCases] = useState<SupervisionCase[]>([])
  const [dids, setDids] = useState<{ did: string; applicationId: string }[]>([])
  const [excludedLegacyCount, setExcludedLegacyCount] = useState(0)
  const [selectedId, setSelectedId] = useState('')
  const [targetDid, setTargetDid] = useState('')
  const [purpose, setPurpose] = useState('')
  const [allegation, setAllegation] = useState('')
  const [evidenceRef, setEvidenceRef] = useState('')
  const [rejectNote, setRejectNote] = useState('')
  const [nextSupervisor, setNextSupervisor] = useState<(typeof supervisorIds)[number]>('supervisor-a')
  const [forensic, setForensic] = useState<ForensicResult | undefined>()
  const [identity, setIdentity] = useState<RevealedIdentity | undefined>()
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const isSupervisor = session.role === 'supervisor'
  const selected = useMemo(() => cases.find(item => item.caseId === selectedId), [cases, selectedId])

  async function refreshCases() {
    const result = await getCases()
    setCases(result.items)
    setSelectedId(current => result.items.some(item => item.caseId === current)
      ? current : result.items[0]?.caseId ?? '')
  }

  useEffect(() => {
    let active = true
    Promise.all([getCases(), getTraceTargets()]).then(([caseResult, targetResult]) => {
      if (!active) return
      setCases(caseResult.items)
      setSelectedId(current => caseResult.items.some(item => item.caseId === current)
        ? current : caseResult.items[0]?.caseId ?? '')
      setDids(targetResult.items)
      setExcludedLegacyCount(targetResult.excludedLegacyCount)
      setTargetDid(current => current || targetResult.items[0]?.did || '')
    }).catch(reason => {
      if (!active) return
      setError(reason instanceof Error ? reason.message : '无法读取监管案件或 D6 DID 目录')
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  async function runAction(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await action()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '监管操作失败')
    } finally {
      setBusy(false)
    }
  }

  function createReport() {
    if (!targetDid || !purpose.trim() || allegation.trim().length < 4) {
      setError('请选择已完成 D6 的 DID，并填写追溯用途和至少 4 个字符的举报说明。')
      return
    }
    void runAction(async () => {
      const created = await reportCase({
        did: targetDid,
        purpose: purpose.trim(),
        allegation: allegation.trim(),
        evidenceRef: evidenceRef.trim(),
      })
      await refreshCases()
      setSelectedId(created.caseId)
      setPurpose('')
      setAllegation('')
      setEvidenceRef('')
      setNotice('举报已登记。必须由两名不同监管员分别签名立案后，才可进行协查和身份揭露。')
    })
  }

  function signCase() {
    if (!selected || !isSupervisor) return
    void runAction(async () => {
      const approval = await createDemoApproval({
        caseId: selected.caseId,
        did: selected.subjectDid,
        purpose: selected.purpose,
      })
      await approveCase(selected.caseId, approval)
      await refreshCases()
      setNotice('监管员签名已提交；由 AP 按其监管员名录独立核验，凑足两名不同签名后才会立案。')
    })
  }

  function rejectSelected() {
    if (!selected || !isSupervisor || !rejectNote.trim()) return
    void runAction(async () => {
      await rejectCase(selected.caseId, rejectNote.trim())
      await refreshCases()
      setRejectNote('')
      setNotice('案件已驳回，终态不可逆。')
    })
  }

  function discloseSelected() {
    if (!selected || !isSupervisor) return
    void runAction(async () => {
      const result = await discloseCase(selected.caseId)
      setForensic(result)
      await refreshCases()
      setNotice('AP 已核验双人签名并返回协作密文；TP 完成身份绑定校验，取证包已加密封存。')
    })
  }

  function loadForensic() {
    if (!selected) return
    void runAction(async () => {
      const result = await getForensicPackage(selected.caseId)
      setForensic(result)
      setNotice('已读取仅对本案指定监管员开放的加密取证包；页面不解密或显示身份明文。')
    })
  }

  function loadIdentity() {
    if (!selected || !isSupervisor) return
    void runAction(async () => {
      const result = await getRevealedIdentity(selected.caseId)
      setIdentity(result)
      setNotice('身份信息已通过本案加密取证包解封；本次调阅已留审计记录。')
    })
  }

  function switchSupervisor() {
    void runAction(async () => {
      const selectedSupervisor = nextSupervisor
      await onSwitchSupervisor(selectedSupervisor)
      setIdentity(undefined)
      setForensic(undefined)
      setNextSupervisor(selectedSupervisor === 'supervisor-a' ? 'supervisor-b' : 'supervisor-a')
      setNotice(`已切换为 ${selectedSupervisor} 的本地模拟监管员会话。`)
    })
  }

  const hasSigned = Boolean(selected?.approvers.includes(session.subject))

  return <section className="tp-page">
    <div className="tp-heading">
      <div>
        <div className="eyebrow">TRUST PROVIDER / SUPERVISION</div>
        <h1>恶意行为追溯</h1>
        <p className="lede">使用真实 D6 DID 创建案件；双人签名立案并经 AP 校验后生成取证包，再由指定监管员授权调阅身份信息。</p>
      </div>
      <span className="demo-tag">本地 test-adapter</span>
    </div>

    <form className="case-compose" onSubmit={event => { event.preventDefault(); createReport() }}>
      <label htmlFor="trace-did">目标 DID</label>
      {dids.length > 0
        ? <select id="trace-did" required value={targetDid} onChange={event => setTargetDid(event.target.value)}>
          <option value="">选择已完成 D6 的 DID</option>
          {dids.map(item => <option key={item.did} value={item.did}>{item.applicationId} · {shortDid(item.did)}</option>)}
        </select>
        : <p className="queue-empty">{excludedLegacyCount > 0
          ? `有 ${excludedLegacyCount} 条旧版演示 DID 因监管密钥或密文未持久化而无法追溯；请在本版本重新签发凭证。`
          : '当前没有可追溯的 D6 DID。先完成一条身份申请流程。'}</p>}
      <label htmlFor="case-purpose">追溯用途</label>
      <input id="case-purpose" value={purpose} onChange={event => setPurpose(event.target.value)}
        placeholder="例如：调查智能体涉嫌冒用身份的投诉" />
      <label htmlFor="case-allegation">举报说明</label>
      <textarea id="case-allegation" value={allegation} onChange={event => setAllegation(event.target.value)}
        placeholder="说明涉嫌恶意行为及其与目标 DID 的关联" rows={3} />
      <label htmlFor="case-evidence">证据编号（可选）</label>
      <div className="compose-row">
        <input id="case-evidence" value={evidenceRef} onChange={event => setEvidenceRef(event.target.value)}
          placeholder="内部证据编号或不可变存储引用" />
        <button type="submit" disabled={busy || !dids.length}>登记举报</button>
      </div>
    </form>

    {error && <div className="notice-panel trace-error" role="alert">{error}</div>}
    {notice && <div className="notice-panel trace-notice" role="status">{notice}</div>}
    <div className="review-layout supervision-layout">
      <div className="queue" aria-label="监管案件">
        {cases.map(item => <button key={item.caseId}
          className={`queue-item ${item.caseId === selectedId ? 'chosen' : ''}`}
          onClick={() => { setSelectedId(item.caseId); setForensic(undefined); setIdentity(undefined); setNotice('') }}>
          <span className={`queue-status ${item.state === 'sealed' || item.state === 'filed' ? 'approved' : item.state === 'rejected' ? 'rejected' : ''}`} />
          <span className="queue-main"><strong>{item.caseId}</strong><small>{item.allegation}</small></span>
          <span className={`state-label ${item.state === 'sealed' || item.state === 'filed' ? 'approved' : ''}`}>{stateLabels[item.state]}</span>
        </button>)}
        {loading && <div className="queue-empty">正在读取案件…</div>}
        {!loading && !error && !cases.length && <div className="queue-empty">尚无案件。可从上方选择真实 DID 登记举报。</div>}
      </div>

      {selected && <article className="application-detail">
        <div className="detail-head">
          <div><div className="eyebrow">CASE / {selected.caseId}</div><h2>受控身份追溯</h2></div>
          <span className={`state-pill ${selected.state === 'sealed' || selected.state === 'filed' ? 'approved' : selected.state === 'rejected' ? 'rejected' : ''}`}>
            {stateLabels[selected.state]}
          </span>
        </div>
        <div className="detail-grid">
          <div className="detail-block"><span className="detail-label">举报说明</span><strong>{selected.allegation}</strong></div>
          <div className="detail-block"><span className="detail-label">追溯用途</span><strong>{selected.purpose}</strong></div>
          <div className="detail-block"><span className="detail-label">立案签名</span><strong>{selected.approvalCount}/2 · {selected.approvers.join('、') || '等待签名'}</strong></div>
          <div className="detail-block"><span className="detail-label">登记时间</span><strong>{selected.reportedAt}</strong></div>
          {selected.evidenceRef && <div className="detail-block"><span className="detail-label">证据编号</span><strong>{selected.evidenceRef}</strong></div>}
        </div>
        <details className="trace-long-value"><summary>查看目标 DID（{shortDid(selected.subjectDid)}）</summary><code>{selected.subjectDid}</code></details>

        <div className="decision-area trace-actions">
          <label>双人立案与协查 <em>AP 会独立验证两份监管员签名</em></label>
          {isSupervisor
            ? <div className="trace-session-switch">
              <span>当前签署人：<strong>{session.subject}</strong></span>
              <select value={nextSupervisor} onChange={event => setNextSupervisor(event.target.value as typeof nextSupervisor)}>
                {supervisorIds.filter(id => id !== session.subject).map(id => <option key={id} value={id}>{id}</option>)}
                <option value={session.subject}>{session.subject}</option>
              </select>
              <button type="button" className="secondary-action" disabled={busy} onClick={switchSupervisor}>切换监管员</button>
            </div>
            : <div className="trace-session-switch">
              <span>当前会话：{session.subject}（{session.role}）</span>
              <select value={nextSupervisor} onChange={event => setNextSupervisor(event.target.value as typeof nextSupervisor)}>
                {supervisorIds.map(id => <option key={id} value={id}>{id}</option>)}
              </select>
              <button type="button" className="secondary-action" disabled={busy} onClick={switchSupervisor}>开始监管员演示</button>
            </div>}
          {selected.state === 'reported' && <div className="decision-actions">
            <button type="button" className="approve-button" disabled={!isSupervisor || busy || hasSigned || selected.approvalCount >= 2}
              onClick={signCase}>
              {hasSigned ? '当前监管员已签名' : isSupervisor ? '签署立案' : '需切换监管员后签署'}
            </button>
            <input aria-label="驳回理由" value={rejectNote} onChange={event => setRejectNote(event.target.value)}
              placeholder="不予受理理由" />
            <button type="button" className="reject-button" disabled={!isSupervisor || busy || !rejectNote.trim()}
              onClick={rejectSelected}>驳回</button>
          </div>}
          {(selected.state === 'filed' || selected.state === 'investigating') && <div className="decision-actions">
            <button type="button" className="approve-button" disabled={!isSupervisor || busy} onClick={discloseSelected}>
              {selected.state === 'investigating' ? '重试 AP 协查与揭露' : '向 AP 发起协查并生成取证包'}
            </button>
          </div>}
        </div>

        {selected.state === 'sealed' && <div className="success-panel">
          <span className="success-icon">✓</span>
          <div><strong>取证包已加密封存</strong>
            <p>双人立案和 AP 协查已通过，身份与凭证绑定校验成功。只有本案指定监管员可调阅解封后的身份信息。</p>
            {selected.forensicDigest && <code>{selected.forensicDigest}</code>}
            <button type="button" className="secondary-action" disabled={!isSupervisor || busy} onClick={loadForensic}>
              读取加密取证包
            </button>
            <button type="button" className="approve-button" disabled={!isSupervisor || busy} onClick={loadIdentity}>
              调阅恶意用户身份信息
            </button>
          </div>
        </div>}
        {forensic?.caseId === selected.caseId && <details className="trace-forensic">
          <summary>加密取证包（仅密文，点击展开）</summary>
          <p>该内容使用本案指定监管员的加密公钥封装。身份信息需通过上方受控调阅步骤获取。</p>
          <pre>{JSON.stringify(forensic.forensic, null, 2)}</pre>
        </details>}
        {identity?.caseId === selected.caseId && <section className="detail-section trace-identity" aria-label="已授权调阅的恶意用户身份信息">
          <div className="section-title">恶意用户身份信息 <span>已核验 · 调阅人 {identity.accessedBy} · {identity.accessedAt}</span></div>
          <div className="detail-grid">
            {Object.entries(identity.pii).map(([key, value]) => <div className="detail-block" key={key}>
              <span className="detail-label">{key}</span><strong>{value}</strong>
            </div>)}
            <div className="detail-block"><span className="detail-label">身份核验</span><strong>{identity.identityVerified ? 'DID 与身份凭证绑定校验通过' : '未通过'}</strong></div>
            <div className="detail-block"><span className="detail-label">生物特征材料</span><strong>{identity.biFields.join('、') || '无'}</strong></div>
          </div>
          <p className="detail-label">原始生物特征不在此页面展示；身份明文仅在完成双人立案、AP 协查且由指定监管员调阅后返回。</p>
        </section>}
      </article>}
    </div>
  </section>
}
