import { get, post, request, ApiError } from './api-client'
import type { ApplicationSummary, Initialization, Timeline } from '../types'

const root = '/api/user/v1/applications'

export type LocalSessionStatus = {
  enabled: boolean
  authenticated: boolean
  owner: string | null
  profile?: string
  userControlledExecution?: boolean
}

export const getInitialization = () => get<Initialization>('/api/user/v1/initialize')

export const listApplications = () => get<{ items: ApplicationSummary[] }>(root)

export const getLocalSession = () => get<LocalSessionStatus>('/api/user/v1/local-session')

export const startLocalSession = () =>
  post<Omit<LocalSessionStatus, 'authenticated'> & { expiresIn: number; identity: string }>(
    '/api/user/v1/local-session', {},
  )

export const endLocalSession = () =>
  request<{ loggedOut: boolean }>('/api/user/v1/local-session', { method: 'DELETE' })

export const createApplication = (body: { pii: Record<string, string>; bi: Record<string, string> }) =>
  post<Timeline>(root, body)

export const getTimeline = (applicationId: string) =>
  get<Timeline>(`${root}/${encodeURIComponent(applicationId)}/timeline`)

export const transition = (applicationId: string, action: string, body: Record<string, unknown> = {}) =>
  post<Timeline>(`${root}/${encodeURIComponent(applicationId)}/${encodeURIComponent(action)}`, body)

export { ApiError }
