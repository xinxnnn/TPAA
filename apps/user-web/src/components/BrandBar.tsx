import type { Initialization } from '../types'

type Props = {
  initialization: Initialization | null
  testAdapterSessionActive?: boolean
}

export function BrandBar({ initialization, testAdapterSessionActive = false }: Props) {
  return <header className="brand-bar">
    <div className="brand-inner">
      <div className="brand-mark" aria-hidden="true">AG</div>
      <div className="brand-copy"><strong>TPAA 密码与身份凭证工作台</strong><span>协议参数 · 身份审核 · PHC 生命周期</span></div>
      <div className="account-area">
        <span className="avatar" aria-hidden="true">人</span>
        <span className="account-name" title={initialization?.owner ?? ''}>{initialization?.owner ?? (testAdapterSessionActive ? '本地 test-adapter' : '未连接')}</span>
      </div>
    </div>
  </header>
}
