// TPAA 可信第三方控制台 访问后端的唯一出口。
//
// 红线（见 ARCHITECTURE.md §10，由 scripts/check_frontend_boundary.py 静态强制）：
//   ✅ 只允许 /api/tp —— 对应 tp 区：identity-service、review-service、phc-service、did-service、supervision-service
//   ❌ 禁止在前端拼接/硬编码其他区的路径（/api/tp、/api/ap、/api/user、/api/ops）
//   ❌ 前端不做加解密、不持有密钥；SecInfo 信封只在后端构造

export const ZONE = 'tp' as const
export const BASE_URL = '/api/tp' as const
export const UPSTREAM_SERVICES = ['identity-service', 'review-service', 'phc-service', 'did-service', 'supervision-service'] as const

export interface ApiErrorBody {
  code: string
  message: string
  traceId?: string
}

export class ApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message ?? `HTTP ${status}`)
  }
}

export function isSessionCurrent(expires: string): boolean {
  const timestamp = /(?:Z|[+-]\d{2}:\d{2})$/i.test(expires) ? expires : `${expires}Z`
  const expiresAt = Date.parse(timestamp)
  return Number.isFinite(expiresAt) && expiresAt > Date.now()
}

function assertSameZone(path: string): void {
  if (!path.startsWith(BASE_URL)) {
    // 跨域直连在前端层直接抛错 —— 必须改走后端的 coordination 服务
    throw new Error(`[boundary] ${ZONE} 区前端禁止访问 ${path}（只允许 ${BASE_URL}）`)
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  assertSameZone(path)
  let authorization: Record<string, string> = {}
  const rawSession = sessionStorage.getItem('tpaa.tp.demo-reviewer-session')
  if (rawSession) {
    try {
      const session = JSON.parse(rawSession) as { token?: string; expires?: string }
      if (session.token && session.expires && isSessionCurrent(session.expires)) {
        authorization = { Authorization: `Bearer ${session.token}` }
      } else {
        sessionStorage.removeItem('tpaa.tp.demo-reviewer-session')
      }
    } catch {
      sessionStorage.removeItem('tpaa.tp.demo-reviewer-session')
    }
  }
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...authorization, ...(init?.headers ?? {}) },
  })
  if (!res.ok) {
    let body: ApiErrorBody = { code: 'UNKNOWN', message: res.statusText }
    try {
      const parsed = (await res.json()) as Partial<ApiErrorBody> & { detail?: string }
      body = { code: String(parsed.code ?? res.status),
               message: parsed.message ?? parsed.detail ?? res.statusText }
    } catch {
      /* 保留默认 body */
    }
    throw new ApiError(res.status, body)
  }
  return (await res.json()) as T
}

export const get = <T,>(p: string) => request<T>(p)
export const post = <T,>(p: string, body: unknown) =>
  request<T>(p, { method: 'POST', body: JSON.stringify(body) })
