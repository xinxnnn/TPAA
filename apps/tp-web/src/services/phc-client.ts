import { get } from './api-client'

export type PhcQueueItem = {
  applicationId: string
  receivedAt: string
  reviewState: string
  issued: boolean
  finalized: boolean
  phcVersion: number | null
  phcDigest: string | null
}

export type DidDirectoryItem = {
  applicationId: string
  did: string
  phcVersion: number
  phcDigest: string
}

export const getPhcReviewerQueue = () =>
  get<{ items: PhcQueueItem[] }>('/api/tp/v1/phc/reviewer-queue')

export const getDidDirectory = () =>
  get<{ items: DidDirectoryItem[] }>('/api/tp/v1/phc/did-directory')
