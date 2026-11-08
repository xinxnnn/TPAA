// 跨四端共用的请求工具：只做「序列化 + 错误归一」，
// 具体的 BASE_URL 与区划属由各 App 的 services/api-client.ts 决定（不允许下沉到 shared）。

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

export function toQuery(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) usp.set(k, String(v))
  }
  const s = usp.toString()
  return s ? `?${s}` : ''
}
