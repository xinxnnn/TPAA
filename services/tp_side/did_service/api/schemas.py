"""did-service 的 HTTP 契约。

★ `identityHash` 接收十六进制字符串而非整数 —— 与 agent-service 同一条理由：
    它是 256 位，JSON number 会被 float64 静默截断，截断后依然"看起来像个数"。

★ 响应里**没有 cscid**。密文也不给：它是"打开身份的钥匙胚"，
    发出去一次就多一份复制，而拿到它的人只要再拿到监管私钥就能还原身份。
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class RegisterIn(BaseModel):
    did: str = Field(min_length=1)
    identityHash: str = Field(description="H(ID)，64 位十六进制")
    parentDid: str = ""
    ecidRef: str = ""
    confirmedByUser: bool = False
    confirmEvidence: dict | None = None

    @field_validator("identityHash")
    @classmethod
    def _hex64(cls, v: str) -> str:
        s = v.strip().lower().removeprefix("0x")
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            raise ValueError("identityHash 必须是 64 位十六进制")
        if int(s, 16) == 0:
            raise ValueError("identityHash 不能为 0")
        return s


class RegisterOut(BaseModel):
    did: str
    parentDid: str
    agentType: str
    registeredAt: str
    cscidSealed: bool


class DidOut(BaseModel):
    did: str
    parentDid: str
    agentType: str
    state: str
    ecidRef: str = ""
    revokedAt: str = ""
    revokeReason: str = ""
    revokeSource: str = ""
    registeredAt: str = ""
    confirmedByUser: bool = False


class TraceOut(BaseModel):
    did: str
    chain: list[str]
    root: str
    depth: int


class ChildrenOut(BaseModel):
    did: str
    children: list[str]


class RevealIn(BaseModel):
    caseRef: str = Field(min_length=1, description="案由；无案由的取用不可审计")
    requestedBy: str = Field(min_length=1)


class RevealOut(BaseModel):
    did: str
    cscid: str
    caseRef: str


class RevokeIn(BaseModel):
    did: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    by: str = ""


class RevokeOut(BaseModel):
    root: str
    revoked: list[str]
    alreadyRevoked: list[str]


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = [
    "RegisterIn", "RegisterOut", "DidOut", "TraceOut", "ChildrenOut",
    "RevealIn", "RevealOut", "RevokeIn", "RevokeOut", "ErrorOut",
]
