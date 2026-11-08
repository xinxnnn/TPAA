export type TimelineEvent = {
  stage: string
  status: string
  at?: string
  artifacts?: Record<string, unknown>
}

export type CmmCategory = { id: string; options: string[] }

export type Timeline = {
  applicationId: string
  state: string
  nextAction?: string | null
  events: TimelineEvent[]
  catalog?: CmmCategory[]
  issueFailure?: { stage?: string; error?: string; message?: string; resolution?: string }
}

export type ApplicationSummary = {
  applicationId: string
  state: string
  createdAt?: string | null
  did?: string | null
  digest?: string | null
}

export type Credential = Record<string, unknown>

export type Initialization = {
  profile: string
  owner: string
  userSignPk: string
  paramsId: string
  publicParameters: Record<string, unknown>
  publicKeys: Record<string, unknown>
  checks: { executionProfile: string; userControlledExecution: boolean; [key: string]: unknown }
}

export type Selection = { moduleId: string; version: string }
