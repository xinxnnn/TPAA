// TPAA 平台运营台 访问后端的唯一出口。
//
// 红线（见 ARCHITECTURE.md §10，由 scripts/check_frontend_boundary.py 静态强制）：
//   ✅ 只允许 /api/ops —— 对应 ops 区：gateway、policy-service、audit-service、coordination
//   ❌ 禁止在前端拼接/硬编码其他区的路径（/api/tp、/api/ap、/api/user、/api/ops）
//   ❌ 前端不做加解密、不持有密钥；SecInfo 信封只在后端构造

export const ZONE = 'ops' as const
export const BASE_URL = '/api/ops' as const
export const UPSTREAM_SERVICES = ['gateway', 'policy-service', 'audit-service', 'coordination'] as const

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

function assertSameZone(path: string): void {
  if (!path.startsWith(BASE_URL)) {
    // 跨域直连在前端层直接抛错 —— 必须改走后端的 coordination 服务
    throw new Error(`[boundary] ${ZONE} 区前端禁止访问 ${path}（只允许 ${BASE_URL}）`)
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  assertSameZone(path)
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  })
  if (!res.ok) {
    let body: ApiErrorBody = { code: 'UNKNOWN', message: res.statusText }
    try {
      body = (await res.json()) as ApiErrorBody
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
