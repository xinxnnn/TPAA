import { get, post } from './api-client'

export type SupervisionCase = {
  caseId: string
  subjectDid: string
  reporter: string
  allegation: string
  evidenceRef: string
  state: 'reported' | 'filed' | 'investigating' | 'disclosed' | 'sealed' | 'rejected' | 'closed'
  reportedAt: string
  filedAt: string
  purpose: string
  approvers: string[]
  approvalCount: number
  forensicDigest: string
  sealedAt: string
}

export type ForensicResult = {
  caseId: string
  forensic: Record<string, unknown>
  forensicDigest: string
}

export type RevealedIdentity = {
  caseId: string
  did: string
  identityVerified: boolean
  pii: Record<string, string>
  biFields: string[]
  purpose: string
  accessedBy: string
  accessedAt: string
  forensicDigest: string
}

export const getCases = () => get<{ items: SupervisionCase[] }>('/api/tp/v1/cases')

export const getTraceTargets = () =>
  get<{ items: { did: string; applicationId: string }[]; excludedLegacyCount: number }>(
    '/api/tp/v1/targets',
  )

export const reportCase = (input: {
  did: string
  purpose: string
  allegation: string
  evidenceRef: string
}) => post<SupervisionCase>('/api/tp/v1/cases', {
  did: input.did,
  purpose: input.purpose,
  allegation: input.allegation,
  evidenceRef: input.evidenceRef,
})

export const createDemoApproval = (input: {
  caseId: string
  did: string
  purpose: string
}) => post<{ signPk: string; sig: string }>('/api/tp/local-demo/case-approval', input)

export const approveCase = (caseId: string, approval: { signPk: string; sig: string }) =>
  post<SupervisionCase>(`/api/tp/v1/cases/${encodeURIComponent(caseId)}/approve`, { approval })

export const rejectCase = (caseId: string, note: string) =>
  post<SupervisionCase>(`/api/tp/v1/cases/${encodeURIComponent(caseId)}/reject`, { note })

export const discloseCase = (caseId: string) =>
  post<ForensicResult>(`/api/tp/v1/cases/${encodeURIComponent(caseId)}/disclose`, {})

export const getForensicPackage = (caseId: string) =>
  get<ForensicResult>(`/api/tp/v1/cases/${encodeURIComponent(caseId)}/forensic`)

export const getRevealedIdentity = (caseId: string) =>
  get<RevealedIdentity>(`/api/tp/v1/cases/${encodeURIComponent(caseId)}/identity`)
