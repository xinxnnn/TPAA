"""policy-service 的 HTTP 契约。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class RevokeIn(BaseModel):
    rootDid: str = Field(min_length=1)
    # ★ 必填。没有案由的吊销，事后无法解释是谁为什么关掉了谁。
    caseRef: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    issuedBy: str = ""


class RevokeOut(BaseModel):
    orderId: str
    state: str
    revoked: list[str] = Field(default_factory=list)
    alreadyRevoked: list[str] = Field(default_factory=list)
    notified: list[str] = Field(default_factory=list)
    failure: str = ""


class OrderOut(BaseModel):
    orderId: str
    rootDid: str
    caseRef: str
    reason: str
    issuedBy: str = ""
    issuedAt: str = ""
    state: str
    revoked: list[str] = Field(default_factory=list)
    notified: list[str] = Field(default_factory=list)
    failure: str = ""


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = ["RevokeIn", "RevokeOut", "OrderOut", "ErrorOut"]
