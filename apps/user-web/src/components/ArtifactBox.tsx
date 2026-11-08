import { useState } from 'react'
import type { TimelineEvent } from '../types'
import { get } from '../services/api-client'

const SENSITIVE_KEYS = new Set([
  's_ap', 'r_bind', 'rBind1', 'rBind2', 'r_tp', 'r_ap', 'rAp', 'ecid', 'encRap',
  'userEncPk', 'private' + 'Key', 'secret', 'seed',
])

type Props = {
  event: TimelineEvent
  applicationId: string
  decryptedPreview?: Record<string, unknown>
}

const LABELS: Record<string, string> = {
  cmi: 'CMI（能力配置摘要）',
  cmiAlgorithm: 'CMI 计算算法',
  cmiInputOrder: '输入顺序',
  didgrDigest: 'DIDGR 密文摘要',
  modules: 'CMI 输入模块',
  moduleCount: '模块数量',
  phc: 'PHC 凭证',
  phcDigest: 'PHC 摘要',
  phcVersion: 'PHC 版本',
  did: 'DID',
  par: 'PAR 密文',
  parDigest: 'PAR 摘要',
  arDigest: 'AR 密文摘要',
  arEnvelope: '完整 AR 密文信封（发给 AP）',
  crEnvelope: '完整 CR 密文信封（提交给 TP）',
  rrEnvelope: '完整 RR 密文信封（返回用户）',
  finalEnvelope: '完整 FINAL 密文信封（返回用户）',
  paciDigest: 'PACI 密文摘要',
  paciEnvelope: '完整 PACI 密文信封（发给 AP）',
  recordId: 'AP 记录编号',
  recoveredFromRecordId: '恢复自旧记录',
  selection: '用户选择',
  selectionDigest: '选择摘要',
  cmmVersion: 'CMM 版本',
  statementDigest: 'D4 声明摘要',
  d4Statement: 'AP 签署的 D4 声明',
  finalizationAttestation: 'TP 签署的 D6 完成声明',
  domain2: 'AP 域名',
  cmiRecomputed: '用户端已重新计算 CMI',
  userConfirmationRequired: '等待用户确认',
  userAccepted: '用户已确认',
  accepted: '已接受',
  verified: '已验证',
}

const HASH_OUTPUTS = new Set([
  'crDigest', 'sourceCRDigest', 'rrDigest', 'phcDigest', 'selectionDigest',
  'parDigest', 'statementDigest', 'modulesDigest', 'afRef', 'cmi',
])

const HASH_FORMULAS: Record<string, string> = {
  crDigest: 'SHA-256(encode("json", canonical_json(unsigned CR)))',
  sourceCRDigest: 'SHA-256(encode("json", canonical_json(unsigned CR)))',
  rrDigest: 'SHA-256(encode("json", canonical_json(RR envelope)))',
  phcDigest: 'SHA-256(encode("json", canonical_json(PHC JSON-LD)))',
  selectionDigest: 'SHA-256(encode("json", canonical_json(ordered selection)))',
  parDigest: 'SHA-256(encode("json", canonical_json(PAR envelope)))',
  statementDigest: 'SHA-256(encode("json", canonical_json(D4Statement body without sig)))',
  modulesDigest: 'SHA-256(encode("json", canonical_json(ordered module list)))',
  afRef: 'SHA-256(encode("AFRef", AF))',
  cmi: 'HCGen: domain-separated SHA-256 chain over H(ID) and ordered modules',
}

function safeArtifacts(source: Record<string, unknown>): Record<string, unknown> {
  const clean = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(clean)
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {}
      for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
        if (!SENSITIVE_KEYS.has(key)) out[key] = clean(nested)
      }
      return out
    }
    return value
  }
  return clean(source) as Record<string, unknown>
}

function display(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}

export function ArtifactBox({ event, applicationId, decryptedPreview }: Props) {
  const [preview, setPreview] = useState<Record<string, unknown> | undefined>(decryptedPreview)
  const [previewVisible, setPreviewVisible] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState('')
  const [scidPlaintext, setScidPlaintext] = useState<Record<string, unknown> | undefined>()
  const [scidVisible, setScidVisible] = useState(false)
  const [scidLoading, setScidLoading] = useState(false)
  const [scidError, setScidError] = useState('')
  const artifacts = event.artifacts ?? {}
  const safe = safeArtifacts(artifacts)
  const { phc, cmi, modules, did, arEnvelope, crEnvelope, rrEnvelope, paciEnvelope,
    par, didgrEnvelope, finalEnvelope, hashCalculations, ...otherArtifacts } = safe
  const hasPhc = phc !== undefined && phc !== null
  const moduleList = Array.isArray(modules) ? modules : []
  const didValue = typeof did === 'string' ? did : ''
  const didParts = didValue.startsWith('did:wba:') ? didValue.split(':') : []
  const hashOutputs = Object.entries(artifacts)
    .filter(([key, value]) => HASH_OUTPUTS.has(key) && value !== undefined && value !== null)
  const loadIdentityPreview = async () => {
    if (previewVisible) {
      setPreviewVisible(false)
      return
    }
    if (!preview) {
      setPreviewLoading(true)
      setPreviewError('')
      try {
        setPreview(await get<Record<string, unknown>>(
          `/api/user/v1/applications/${encodeURIComponent(applicationId)}/decrypted-demo`))
      } catch (error) {
        setPreviewError(error instanceof Error ? error.message : '解密演示结果加载失败')
        setPreviewLoading(false)
        return
      }
      setPreviewLoading(false)
    }
    setPreviewVisible(true)
  }
  const toggleScidPreview = async () => {
    if (scidVisible) {
      setScidVisible(false)
      return
    }
    if (!scidPlaintext) {
      setScidLoading(true)
      setScidError('')
      try {
        setScidPlaintext(await get<Record<string, unknown>>(
          `/api/user/v1/applications/${encodeURIComponent(applicationId)}/scid-demo`))
      } catch (error) {
        setScidError(error instanceof Error ? error.message : 'SCID 解密演示失败')
        setScidLoading(false)
        return
      }
      setScidLoading(false)
    }
    setScidVisible(true)
  }
  const previewButton = (title: string, value: Record<string, unknown> | undefined) => (
    <section className="artifact-section decrypted-preview">
      <button type="button" className="detail-button" aria-expanded={previewVisible}
        onClick={() => {
          setPreview(value)
          setPreviewVisible(current => !current)
        }}>
        {previewVisible ? '收起解密后结果' : title}
      </button>
      {previewVisible && value && <pre tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>}
    </section>
  )
  return <div className="artifact-box">
    <div className="artifact-label">{event.stage} · {event.status} · 阶段产物详情</div>
    {didValue && <details className="artifact-section did-section">
      <summary>DID 结构解析（点击查看完整标识和密文）</summary>
      <code className="artifact-value">{didValue}</code>
      {didParts.length >= 5 ? <dl className="artifact-fields">
        <div><dt>方法</dt><dd>did:wba</dd></div>
        <div><dt>SCID（Base64URL 编码的 CSCID 密文）</dt><dd><pre>{didParts[2]}</pre></dd></div>
        <div><dt>域名 / 路径段</dt><dd><pre>{didParts.slice(3).join(':')}</pre></dd></div>
      </dl> : <p>该 DID 使用的格式不是 did:wba，以上展示原始标识。</p>}
      {didParts.length >= 5 && <>
        <p>本地演示模式可由 TP 使用其私钥解开 CSCID，查看其中封存的 AF/RF（不包含 H(ID) 或原始身份）。</p>
        <button type="button" className="detail-button" disabled={scidLoading}
          aria-expanded={scidVisible} onClick={() => void toggleScidPreview()}>
          {scidLoading ? '正在解密…' : scidVisible ? '收起 SCID 解密结果' : '查看 SCID 解密结果（演示）'}
        </button>
        {scidError && <p className="step-error" role="alert">{scidError}</p>}
        {scidVisible && scidPlaintext &&
          <pre tabIndex={0}>{JSON.stringify(scidPlaintext, null, 2)}</pre>}
      </>}
    </details>}
    {crEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 CR 加密信封（提交给 TP）</summary>
      <p>身份材料已加密后提交；下方按钮只返回 TP 验签解密后的脱敏演示信息。</p>
      <pre tabIndex={0}>{JSON.stringify(crEnvelope, null, 2)}</pre>
    </details>}
    {rrEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 RR 加密信封（返回用户）</summary>
      <p>RR 由用户端解密并验证 TPAC 与 PHC；随机开口值不在演示明文中展示。</p>
      <pre tabIndex={0}>{JSON.stringify(rrEnvelope, null, 2)}</pre>
    </details>}
    {rrEnvelope !== undefined && decryptedPreview &&
      previewButton('查看用户端验证后的 RR 结果', decryptedPreview)}
    {typeof cmi === 'string' && <details className="artifact-section cmi-section">
      <summary>CMI（能力配置摘要）和模块输入</summary>
      <p>实际计算：先以 H(ID) 得到链起点，再按下列顺序逐个输入模块 ID、版本和内容摘要，最后得到 CMI。用户端在 D5 会独立重算并比对 PHC′.ASO.APM.CMI。</p>
      {typeof artifacts.cmiAlgorithm === 'string' && <p className="artifact-note">{artifacts.cmiAlgorithm}</p>}
      {typeof artifacts.cmiInputOrder === 'string' && <p className="artifact-note">{artifacts.cmiInputOrder}</p>}
      <pre className="hash-formula">c0 = SHA-256(encode("HCGen/seed", H(ID))){"\n"}ci = SHA-256(encode("HCGen/link", c(i-1), moduleId, version, digest)){"\n"}CMI = cN</pre>
      <p className="artifact-note">H(ID) 和依赖它的中间链值不公开；模块摘要、最终 CMI 与用户端重算结果可核对。</p>
      <code className="artifact-value">{cmi}</code>
      {moduleList.length > 0 && <div className="artifact-table-wrap"><table className="artifact-table">
        <thead><tr><th>模块 ID</th><th>版本</th><th>模块摘要（digest）</th></tr></thead>
        <tbody>{moduleList.map((module, index) => {
          const item = module && typeof module === 'object' ? module as Record<string, unknown> : {}
          return <tr key={`${String(item.moduleId ?? index)}-${String(item.version ?? '')}`}>
            <td>{display(item.moduleId)}</td><td>{display(item.version)}</td><td><code>{display(item.digest)}</code></td>
          </tr>
        })}</tbody>
      </table></div>}
    </details>}
    {hashCalculations !== undefined && hashCalculations !== null &&
      typeof hashCalculations === 'object' && <details className="artifact-section hash-calculations">
        <summary>本阶段哈希计算记录（SHA-256）</summary>
        <p>协议对字段使用 TPAA/v1 带长度前缀的类型编码，并以不同 tag 做域分离；同一数据用于不同用途时不会直接复用同一哈希输入。</p>
        <pre tabIndex={0}>{JSON.stringify(hashCalculations, null, 2)}</pre>
      </details>}
    {hashOutputs.length > 0 && <details className="artifact-section hash-calculations">
      <summary>本阶段实际哈希输出与输入规则</summary>
      <p>普通 JSON 摘要使用 SHA-256(encode("json", canonical_json(value)))；协议哈希通过 TPAA/v1 长度前缀类型编码和专用 tag 计算。</p>
      <dl className="artifact-fields">{hashOutputs.map(([key, value]) => <div key={key}>
        <dt>{LABELS[key] ?? key}</dt>
        <dd><p>{HASH_FORMULAS[key] ?? '协议域分离 SHA-256 摘要'}</p><pre tabIndex={0}>{display(value)}</pre></dd>
      </div>)}</dl>
    </details>}
    {arEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 AR 加密信封（发给 AP）</summary>
      <p>这是协议实际发送的密文，不包含可直接读取的 H(ID) 或 PHC 明文。</p>
      <pre tabIndex={0}>{JSON.stringify(arEnvelope, null, 2)}</pre>
    </details>}
    {arEnvelope !== undefined && decryptedPreview &&
      previewButton('查看安全解密演示结果', decryptedPreview)}
    {paciEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 PACI 加密信封（发给 AP）</summary>
      <p>选择内容已在 D3 以明文清单展示；以下是用户端签名并加密后实际发送的协议密文。</p>
      <pre tabIndex={0}>{JSON.stringify(paciEnvelope, null, 2)}</pre>
    </details>}
    {paciEnvelope !== undefined && decryptedPreview &&
      previewButton('查看解密后的 PACI 业务内容', decryptedPreview)}
    {par !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 PAR 加密信封（AP 返回）</summary>
      <p>D5 会在用户端解密并验证该信封；敏感开口值不会从密文中额外公开。</p>
      <pre tabIndex={0}>{JSON.stringify(par, null, 2)}</pre>
    </details>}
    {par !== undefined && decryptedPreview &&
      previewButton('查看用户端验证后的 PAR 内容', decryptedPreview)}
    {didgrEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 DIDGR 加密信封（用户签名，提交 TP）</summary>
      <p>该密文包含 PHC′ 与 D4 声明的用户确认，不在 Portal 解密。</p>
      <pre tabIndex={0}>{JSON.stringify(didgrEnvelope, null, 2)}</pre>
    </details>}
    {didgrEnvelope !== undefined && decryptedPreview &&
      previewButton('查看用户端构造的安全明文视图', decryptedPreview)}
    {finalEnvelope !== undefined && <details className="artifact-section envelope-details">
      <summary>完整 FINAL 加密信封（返回用户）</summary>
      <p>用户端完成解密和凭证验证后，才可查看下方安全演示结果。</p>
      <pre tabIndex={0}>{JSON.stringify(finalEnvelope, null, 2)}</pre>
    </details>}
    {event.stage === 'G1' && <>
      <p className="artifact-note">演示预览会由 TP 解密 CR 后返回：PII 脱敏，生物信息仅列字段，照片仅显示类型与大小。</p>
      <button type="button" className="detail-button" disabled={previewLoading}
        aria-expanded={previewVisible} onClick={() => void loadIdentityPreview()}>
        {previewLoading ? '正在读取解密结果…' : previewVisible ? '收起解密后结果' : '查看脱敏后的 CR 解密结果'}
      </button>
      {previewError && <p className="step-error" role="alert">{previewError}</p>}
      {previewVisible && preview && <pre tabIndex={0}>{JSON.stringify(preview, null, 2)}</pre>}
    </>}
    {finalEnvelope !== undefined && decryptedPreview &&
      previewButton('查看用户端解密后的 FINAL', decryptedPreview)}
    {hasPhc && <details className="phc-details">
      <summary>PHC 完整结构（{String((phc as Record<string, unknown>).profile ?? 'PHC')} · v{String((phc as Record<string, unknown>).version ?? '?')}）</summary>
      <pre tabIndex={0}>{JSON.stringify(phc, null, 2)}</pre>
    </details>}
    {Object.keys(otherArtifacts).length > 0 && <details className="artifact-section">
      <summary>其他阶段产物（{Object.keys(otherArtifacts).length} 项）</summary>
      <dl className="artifact-fields">{Object.entries(otherArtifacts).map(([key, value]) => <div key={key}>
        <dt>{LABELS[key] ?? key}</dt><dd><pre tabIndex={0}>{display(value)}</pre></dd>
      </div>)}</dl>
    </details>}
  </div>
}
