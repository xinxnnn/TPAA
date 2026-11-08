import { useEffect, useState } from 'react'
import { ApiError, get } from '../../services/api-client'

export default function AuthPage() {
  const [status, setStatus] = useState<'checking' | 'ready' | 'unavailable'>('checking')
  const [message, setMessage] = useState('正在连接用户端服务')

  useEffect(() => {
    let active = true
    get<{ profile: string; paramsId: string; checks: Record<string, string> }>('/api/user/v1/initialize')
      .then(result => {
        if (!active) return
        setStatus('ready')
        setMessage(`协议参数 ${result.paramsId} 已加载。当前执行边界：${result.checks.serverWalletMode ?? '未声明'}`)
      })
      .catch(error => {
        if (!active) return
        setStatus('unavailable')
        setMessage(error instanceof ApiError
          ? `用户端服务未就绪：${error.message}`
          : '用户端服务不可达。请先启动并配置 Portal 服务。')
      })
    return () => { active = false }
  }, [])

  return (
    <section className="flow-page">
      <div className="eyebrow">TPAA V1 / USER WORKSPACE</div>
      <h1>凭证与智能体流程</h1>
      <p className="lede">流程进度由 TP、AP 与用户端服务产生的协议记录显示。</p>
      <div className="notice-panel" role="status" aria-live="polite">
        <strong>{status === 'ready' ? '服务已连接' : status === 'checking' ? '正在连接' : '服务不可用'}</strong>
        <p>{message}</p>
      </div>
      {status === 'ready' && (
        <p className="muted-note">当前服务执行边界可能是本地测试适配器；这不代表用户独立控制密钥。未提供该能力时，不会显示为用户端独立验收。</p>
      )}
    </section>
  )
}
