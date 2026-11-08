// 与 contracts/ 对齐的共享类型（见 ARCHITECTURE.md §19）。
// 这里的字段是四个前端都要用到的最小公约数；区特有的字段放在各 App 的 types 里。

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

/** PHC 申领单状态机，见 §12.1 */
export type PhcApplicationState =
  | 'draft'
  | 'pending_review'
  | 'reviewing'
  | 'approved'
  | 'issuing'
  | 'issued'
  | 'rejected'
  | 'revoked'

/** 智能体凭证状态 */
export type AgentCredentialState = 'active' | 'suspended' | 'revoked' | 'expired'

/** 追溯链路阶段，见 §12 吊销链路 */
export type TraceStage = 'reported' | 'filed' | 'assisting' | 'disclosed' | 'revoked'

export interface AgentSummary {
  did: string
  displayName: string
  parentDid: string | null
  state: AgentCredentialState
  issuedAt: number
  expiresAt?: number
}

export interface PhcSummary {
  applicationId: string
  state: PhcApplicationState
  /** 只传 AF/TPCH 等非秘密值；CRF、RF 密文永不出后端 */
  agentFactor?: string
  updatedAt: number
}
