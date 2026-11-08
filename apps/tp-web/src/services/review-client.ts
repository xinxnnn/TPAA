import { get, post, ApiError } from './api-client'

export type ReviewItem = {
  applicationId: string
  crDigest: string
  receivedAt: string
  state: string
  pii: Record<string, string>
  biFields: string[]
  demoFacePhotoPreview?: string
  review: {
    applicationId: string
    state: string
    approved: boolean
    decisions: { reviewer: string; decision: string; at: string }[]
  } | null
}

export type ReviewQueue = { items: ReviewItem[] }
export type ReviewDecision = {
  applicationId: string
  state: string
  approved: boolean
  decisions: { reviewer: string; decision: string; at: string }[]
}

export const getReviewQueue = () => post<ReviewQueue>('/api/tp/v1/applications/review-queue', {})
export const getReviewDetail = (applicationId: string) =>
  get<ReviewItem>(`/api/tp/v1/applications/${encodeURIComponent(applicationId)}/review`)
export const decideReview = (applicationId: string, decision: 'approve' | 'reject', note: string) =>
  post<ReviewDecision>(`/api/tp/v1/reviews/${encodeURIComponent(applicationId)}`,
    { decision, note })

export { ApiError }
