import type { Selection, Timeline } from '../types'
import { TimelineStep } from './TimelineStep'
import { ModulePicker } from './ModulePicker'

const STAGES = [
  ['INIT', '协议公共参数与参与方公钥'], ['G1', '用户提交身份申请（加密 CR）'],
  ['REVIEW', 'TP 验证申请并人工审批'], ['G3', 'TP 签发初始 PHC / RR'],
  ['G4', '用户验证并接受初始 PHC'], ['D1', '用户构造能力申请 AR'],
  ['D2', 'AP 验证申请并返回 CMM'], ['D3', '用户选择配置并签署 PACI'],
  ['D4', 'AP 计算 CMI、更新 PHC′ 并返回 PAR'],
  ['D5', '用户验证 PAR / CMI 并签署 DIDGR'],
  ['D6', 'TP 验证 DIDGR 并产生 DID / PHC″'],
  ['FINAL', '用户验证并接受最终 PHC'],
] as const

const ACTIONS: Record<string, { stage: string; label: string; endpoint: string }> = {
  issue: { stage: 'G3', label: '申领 PHC', endpoint: 'issue' },
  'accept-g4': { stage: 'G4', label: '接受 PHC', endpoint: 'accept-g4' },
  'start-agent': { stage: 'D1', label: '提交能力申请并获取 CMM', endpoint: 'begin-agent' },
  'build-agent': { stage: 'D3', label: '确认授权配置并提交 PACI', endpoint: 'build-agent' },
  'accept-d5': { stage: 'D5', label: '核验凭证', endpoint: 'accept-d5' },
  'confirm-d5': { stage: 'D5', label: '确认声明并构造 DIDGR', endpoint: 'confirm-d5' },
  'finalize-d6': { stage: 'D6', label: '提交 DIDGR 并签发 FINAL', endpoint: 'finalize-d6' },
  'verify-final': { stage: 'FINAL', label: '在用户端验证 FINAL', endpoint: 'verify-final' },
  'accept-final': { stage: 'FINAL', label: '确认并接受最终 PHC', endpoint: 'accept-final' },
  reconcile: { stage: 'G3', label: '对账签发状态', endpoint: 'reconcile' },
}

type Props = {
  timeline: Timeline
  busy: boolean
  selection: Selection[]
  onSelection: (selection: Selection[]) => void
  onAction: (action: string, body?: Record<string, unknown>) => void
  error?: string
  pendingAction?: string
}

export function WorkflowTimeline({ timeline, busy, selection, onSelection, onAction, error, pendingAction }: Props) {
  const next = timeline.nextAction ? ACTIONS[timeline.nextAction] : undefined
  const eventArtifacts = (stage: string) =>
    timeline.events.find(item => item.stage === stage)?.artifacts ?? {}
  const g4 = eventArtifacts('G4')
  const d5 = eventArtifacts('D5')
  const final = timeline.events.find(item => item.stage === 'FINAL'
    && item.status === 'verified_by_user_executor')?.artifacts ?? {}
  const d3 = eventArtifacts('D3')
  const previews: Record<string, Record<string, unknown> | undefined> = {
    G3: g4.phc ? {
      PHC: g4.phc,
      TPACVerification: '用户端已验证签名、PHC 摘要及 G1 身份绑定',
      omitted: ['TPAC 中的随机开口值', 'H(ID)'],
      note: '来自用户端 G4 解密与验签后的结果。',
    } : undefined,
    D1: g4.phc ? {
      decryptedFields: ['PHC', 'H(ID)', 'TPAC'],
      PHC: g4.phc,
      omitted: ['H(ID)', 'TPAC 中的随机开口值'],
      note: 'PHC 来自用户端 G4 验证；敏感身份派生值与随机开口不展示。',
    } : undefined,
    D3: d3.selection ? {
      cmmVersion: d3.cmmVersion,
      selection: d3.selection,
      note: '这是 PACI 签名并加密前的用户选择明文。',
    } : undefined,
    D4: d5.phc ? {
      PHC: d5.phc,
      modules: d5.modules,
      CMI: d5.cmi,
      D4Statement: d5.d4Statement,
      note: '来自用户端解密并验证 PAR 后的结果；H(ID) 与随机开口不展示。',
    } : undefined,
    D5: d5.didgrEnvelope ? {
      domain2: d5.domain2,
      PHC: d5.phc,
      D4Statement: d5.d4Statement,
      omitted: ['RF（随机秘密值）'],
      note: '展示用户端构造 DIDGR 时确认的字段；随机秘密值不展示。',
    } : undefined,
    D6: final.phc ? {
      DID: final.did,
      PHC: final.phc,
      CMI: final.cmi,
      note: '来自用户端解密并验证 FINAL 后的结果。',
    } : undefined,
  }
  // 阶段状态和下一步动作只来自后端；这里的数组仅决定标题和显示顺序。
  return <section className="card workflow-card" aria-labelledby="workflow-heading">
    <div className="section-heading"><div><span className="section-kicker">TPAA PROTOCOL</span><h2 id="workflow-heading">身份凭证与能力授权流程</h2></div><span className="flow-state">{timeline.state}</span></div>
    <p className="workflow-caption">同一申请编号 <span className="mono">{timeline.applicationId}</span> 贯穿 G1 至 FINAL；详情展示该阶段实际生成的公开产物。</p>
    {timeline.issueFailure && <p className="issue-failure" role="alert">签发待对账：{timeline.issueFailure.resolution ?? timeline.issueFailure.message ?? timeline.issueFailure.error}</p>}
    <ol className="vertical-timeline">{STAGES.map(([code, title], index) => {
      const event = timeline.events.find(item => item.stage === code)
      const active = next?.stage === code
      const action = active && next ? { label: pendingAction === next.endpoint ? '处理中…' : next.label,
        disabled: busy || (next.endpoint === 'build-agent' && selection.length === 0),
        onClick: () => onAction(next.endpoint, next.endpoint === 'build-agent' ? { selection } : {}) } : undefined
      return <TimelineStep key={code} code={code} title={title} index={index} event={event}
        applicationId={timeline.applicationId} decryptedPreview={previews[code]}
        active={active} action={action} error={active ? error : undefined}>
        {code === 'REVIEW' && event?.status === 'pending' && <p className="inline-hint">等待 TP 审核台处理；本页面不能替审核员作出决定。</p>}
        {code === 'D2' && timeline.nextAction === 'build-agent' && <ModulePicker catalog={timeline.catalog ?? []} selection={selection} onChange={onSelection} disabled={busy} />}
        {code === 'D5' && timeline.nextAction === 'confirm-d5' && <p className="inline-hint">PAR/CMI 与 AP 声明已核验；确认后才会构造 DIDGR。此操作不能代替独立用户设备确认。</p>}
        {code === 'FINAL' && timeline.nextAction === 'accept-final' && <p className="inline-hint">用户端已验证最终 PHC 的 TP/AP 签名、DID 绑定与 D4 配置一致性；确认后才接受 FINAL。</p>}
      </TimelineStep>
    })}</ol>
    {timeline.state === 'd6_accepted' && <p className="inline-hint">协议流程已完成：用户已接受最终 PHC。Agent 制品发布和 Runtime 不属于本阶段范围。</p>}
  </section>
}
