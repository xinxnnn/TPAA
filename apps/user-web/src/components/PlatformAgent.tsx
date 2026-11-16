import { useState } from 'react'
import { post } from '../services/api-client'

type LocalAnswer = { answer: string; did: string; model: string; executionLocation: string; memauthStatus: string }

export function PlatformAgent({ applicationId }: { applicationId: string }) {
  const [task, setTask] = useState('')
  const [result, setResult] = useState<LocalAnswer | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit() {
    setBusy(true); setError(''); setResult(null)
    try {
      setResult(await post<LocalAnswer>(
        `/api/user/v1/applications/${encodeURIComponent(applicationId)}/chat-runtime`, { text: task }))
    } catch (e) { setError(e instanceof Error ? e.message : '调用失败') }
    finally { setBusy(false) }
  }
  return <section className="card">
    <h2>本申请颁发的本地个人智能体</h2>
    <p>颁发制品由用户执行器校验并保存在本机。运行需要在本机配置模型 API；密钥不进入颁发包或身份凭证。MemAuth 尚未注册。</p>
    <label>本地实验任务<input value={task} maxLength={8000} onChange={e => setTask(e.target.value)} /></label>
    <button disabled={busy || !task.trim()} onClick={() => void submit()}>{busy ? '执行中…' : '调用本地智能体'}</button>
    {error && <p role="alert">{error}</p>}
    {result && <div><p><strong>回复：</strong>{result.answer}</p>
      <details><summary>查看颁发身份和执行状态</summary>
        <p>执行位置：{result.executionLocation} · 模型：{result.model} · MemAuth：{result.memauthStatus}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{result.did}</pre>
      </details></div>}
  </section>
}
