"""supervision-service 的 HTTP 契约。

★ `DiscloseOut.identityHash` 是**唯一**会把 H(ID) 明文写进响应的地方。
  它出现一次、由调用方当场用掉；案件库里只留摘要。
  如果哪天有人给它加一个"查询接口"，那一步就是把系统变成一个
  "输入 DID 查身份证号"的机器 —— 所以这里没有这样的接口。
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReportIn(BaseModel):
    subjectDid: str = Field(min_length=1)
    reporter: str = Field(min_length=1)
    allegation: str = Field(min_length=4)
    evidenceRef: str = ""


class ReportOut(BaseModel):
    caseId: str
    subjectDid: str
    state: str
    reportedAt: str


class FileIn(BaseModel):
    reviewers: list[str] = Field(min_length=2,
                                 description="两名不同的复核人；同一人签两次不予受理")
    note: str = ""


class FileOut(BaseModel):
    caseId: str
    subjectDid: str
    state: str
    filedAt: str = ""
    reviewers: list[str] = Field(default_factory=list)


class RejectIn(BaseModel):
    reviewer: str = Field(min_length=1)
    note: str = Field(min_length=1)


class InvestigateIn(BaseModel):
    requestedBy: str = Field(min_length=1)


class InvestigateOut(BaseModel):
    caseId: str
    ticketId: str
    state: str
    lineageChain: list[str] = Field(default_factory=list)


class CollectIn(BaseModel):
    ticketId: str = Field(min_length=1)


class DiscloseOut(BaseModel):
    caseId: str
    subjectDid: str
    identityHash: str
    identityDigest: str
    state: str
    verified: bool
    verifyNote: str = ""


class ForensicIn(BaseModel):
    exportedBy: str = Field(min_length=1)


class ForensicOut(BaseModel):
    caseId: str
    subjectDid: str
    state: str
    envelopeDigest: str = ""
    envelopeBytes: int = 0
    chainVerified: bool = False
    verdictReason: str = ""
    sealedAt: str = ""
    timeline: list[dict] = Field(default_factory=list)


class CaseOut(BaseModel):
    caseId: str
    subjectDid: str
    reporter: str = ""
    state: str
    reportedAt: str = ""
    filedAt: str = ""
    reviewers: list[str] = Field(default_factory=list)
    ticketIds: list[str] = Field(default_factory=list)
    lineageChain: list[str] = Field(default_factory=list)
    disclosedHash: str = ""
    disclosedAt: str = ""
    forensicDigest: str = ""
    sealedAt: str = ""
    revokedAt: str = ""


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = [
    "ReportIn", "ReportOut", "FileIn", "FileOut", "RejectIn",
    "InvestigateIn", "InvestigateOut", "CollectIn",
    "DiscloseOut", "ForensicIn", "ForensicOut", "CaseOut", "ErrorOut",
]
