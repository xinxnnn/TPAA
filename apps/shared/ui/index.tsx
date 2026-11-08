// 共用 UI 外壳：四个前端各自独立部署，但共用同一套外观与布局。
// 注意：shared 只放展示型代码；任何与区相关的后端访问都不允许放进 shared。

import type { ReactNode } from 'react'

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

export interface AppShellProps {
  title: string
  zone: Zone
  children: ReactNode
}

export function AppShell(props: AppShellProps) {
  return (
    <div data-zone={props.zone} style={{ fontFamily: 'system-ui, sans-serif', minHeight: '100vh' }}>
      {props.children}
    </div>
  )
}
