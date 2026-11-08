// 四个前端的权限模型互不相通：同一个自然人账号，在 user-web / tp-web / ap-web
// 是三套彼此独立的角色体系，不得在 shared 里做统一角色合并。
//
// 这里只定义会话的抽象形状，各区 App 自己决定 roles 的取值来源与校验方式。

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

export interface Session {
  zone: Zone
  subject: string
  roles: readonly string[]
  expiresAt: number
}

export function hasRole(s: Session, role: string): boolean {
  return s.roles.includes(role)
}

// 会话只允许存 sessionStorage（关闭标签页即失效），禁止 localStorage 持久化（红线 F3）。
const KEY = 'tpaa.session'

export function loadSession(): Session | null {
  const raw = sessionStorage.getItem(KEY)
  return raw ? (JSON.parse(raw) as Session) : null
}

export function saveSession(s: Session): void {
  sessionStorage.setItem(KEY, JSON.stringify(s))
}

export function clearSession(): void {
  sessionStorage.removeItem(KEY)
}
