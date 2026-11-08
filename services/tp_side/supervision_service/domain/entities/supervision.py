"""立案与追溯的领域模型。

整个文件只围绕一条铁律：

    **没立案，什么都别做。**

这不是流程洁癖。监管能还原一个自然人的身份，这条能力必须有一个
"有人在纸上签过字"的开关。代码里这个开关就是 `CaseState.FILED` ——
所有涉及密钥与身份的动作（揭示、取证、吊销）都先看它一眼。

`Case.guard()` 是这条铁律的唯一实现处。任何新加的动作都必须先调它，
而不是各自写一个 `if state != FILED` —— 那样早晚有人漏写一个。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CaseState(str, Enum):
    REPORTED = "reported"          # 举报待受理
    FILED = "filed"                # 已立案（双人复核通过）
    INVESTIGATING = "investigating"  # 协查中（工单已发出）
    DISCLOSED = "disclosed"        # 已揭露（身份已还原，密文已开）
    SEALED = "sealed"              # 已取证（取证包已生成）
    REVOKED = "revoked"            # 已吊销并级联
    REJECTED = "rejected"          # 不予受理
    CLOSED = "closed"


class CaseError(RuntimeError):
    """案件层的拒绝。"""


class NotFiled(CaseError):
    """未立案。这是本服务最重要的一个异常类型 ——
    它必须与"参数错"分开，因为它的含义是"你在越权"，不是"你填错了"。"""


class IllegalCaseTransition(CaseError):
    pass


# 状态迁移表：显式写出来，而不是靠一堆 if。
_ALLOWED: dict[CaseState, set[CaseState]] = {
    CaseState.REPORTED: {CaseState.FILED, CaseState.REJECTED},
    CaseState.FILED: {CaseState.INVESTIGATING, CaseState.REJECTED, CaseState.CLOSED},
    CaseState.INVESTIGATING: {CaseState.DISCLOSED, CaseState.CLOSED},
    CaseState.DISCLOSED: {CaseState.SEALED, CaseState.CLOSED},
    CaseState.SEALED: {CaseState.REVOKED, CaseState.CLOSED},
    CaseState.REVOKED: {CaseState.CLOSED},
    CaseState.REJECTED: set(),
    CaseState.CLOSED: set(),
}


@dataclass
class Case:
    case_id: str
    subject_did: str
    reporter: str = ""
    evidence_ref: str = ""
    allegation: str = ""
    state: CaseState = CaseState.REPORTED
    reported_at: str = ""
    filed_at: str = ""
    # ★ 双人复核：两个人，且不能是同一个人
    reviewers: list[str] = field(default_factory=list)
    reviewers_note: str = ""
    # 协查
    ticket_ids: list[str] = field(default_factory=list)
    lineage_chain: list[str] = field(default_factory=list)
    # AP 答复时回传的 PHC（公开材料）—— 揭露之后要用它复核身份真的对得上
    phc_json: dict = field(default_factory=dict)
    # 揭露结果只存**哈希**，不存 H(ID) 明文 —— 见 disclose usecase
    disclosed_hash: str = ""
    disclosed_at: str = ""
    # 取证
    forensic_digest: str = ""
    forensic_box: dict = field(default_factory=dict)
    sealed_at: str = ""
    revoked_at: str = ""
    notes: list[str] = field(default_factory=list)

    # ---- 铁律 ----
    def guard(self, *allowed: CaseState) -> None:
        """动作前置检查。未立案一律拒，连"看看状态"都不放过。

        为什么连查询也拦：一个能在未立案时反复查询"这个 DID 能否被还原"的接口，
        本身就是一个能把归属关系摸出来的探针。
        """
        if self.state is CaseState.REJECTED:
            raise NotFiled(f"案件 {self.case_id} 已不予受理，不能再执行任何动作")
        if self.state is CaseState.REPORTED:
            raise NotFiled(
                f"案件 {self.case_id} 尚未立案 —— 立案需要两名复核人，"
                "在此之前不得进行任何追溯动作")
        if allowed and self.state not in allowed:
            raise IllegalCaseTransition(
                f"案件 {self.case_id} 当前为 {self.state.value}，"
                f"该动作只允许在 {[s.value for s in allowed]} 时进行")

    def move(self, to: CaseState) -> None:
        if to not in _ALLOWED.get(self.state, set()):
            raise IllegalCaseTransition(
                f"非法状态迁移：{self.state.value} → {to.value}")
        self.state = to

    # ---- 状态迁移动作 ----
    def file(self, *, reviewers: list[str], note: str, at: str) -> None:
        """立案。双人复核 —— 两个人，且不能是同一个人。"""
        people = [r.strip() for r in reviewers if r and r.strip()]
        if len(set(people)) < 2:
            raise CaseError(
                "立案必须由两名不同的复核人签署 —— "
                "同一人签两次等于没有复核，而这一步会打开还原身份的能力")
        self.reviewers = people
        self.reviewers_note = note
        self.filed_at = at
        self.move(CaseState.FILED)

    def reject(self, *, note: str) -> None:
        self.notes.append(note)
        self.move(CaseState.REJECTED)

    def to_json(self) -> dict:
        return {
            "caseId": self.case_id,
            "subjectDid": self.subject_did,
            "reporter": self.reporter,
            "evidenceRef": self.evidence_ref,
            "allegation": self.allegation,
            "state": self.state.value,
            "reportedAt": self.reported_at,
            "filedAt": self.filed_at,
            "reviewers": self.reviewers,
            "reviewersNote": self.reviewers_note,
            "ticketIds": self.ticket_ids,
            "lineageChain": self.lineage_chain,
            "phc": self.phc_json,
            "disclosedHash": self.disclosed_hash,
            "disclosedAt": self.disclosed_at,
            "forensicDigest": self.forensic_digest,
            "forensicBox": self.forensic_box,
            "sealedAt": self.sealed_at,
            "revokedAt": self.revoked_at,
            "notes": self.notes,
        }

    @classmethod
    def from_json(cls, d: dict) -> "Case":
        return cls(
            case_id=d.get("caseId", ""),
            subject_did=d.get("subjectDid", ""),
            reporter=d.get("reporter", ""),
            evidence_ref=d.get("evidenceRef", ""),
            allegation=d.get("allegation", ""),
            state=CaseState(d.get("state", "reported")),
            reported_at=d.get("reportedAt", ""),
            filed_at=d.get("filedAt", ""),
            reviewers=list(d.get("reviewers", [])),
            reviewers_note=d.get("reviewersNote", ""),
            ticket_ids=list(d.get("ticketIds", [])),
            lineage_chain=list(d.get("lineageChain", [])),
            phc_json=d.get("phc", {}) or {},
            disclosed_hash=d.get("disclosedHash", ""),
            disclosed_at=d.get("disclosedAt", ""),
            forensic_digest=d.get("forensicDigest", ""),
            forensic_box=dict(d.get("forensicBox", {})),
            sealed_at=d.get("sealedAt", ""),
            revoked_at=d.get("revokedAt", ""),
            notes=list(d.get("notes", [])),
        )


__all__ = [
    "Case", "CaseState", "CaseError", "NotFiled", "IllegalCaseTransition",
]
