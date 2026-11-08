"""lifecycle-service 的 HTTP 契约。"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class RevocationIn(BaseModel):
    rootDid: str = Field(min_length=1)
    revoked: list[str] = Field(default_factory=list)
    # ★ 必填：广播来自网络，不能只信上游校验过
    caseRef: str = Field(min_length=1)
    reason: str = ""


class RevocationOut(BaseModel):
    rootDid: str
    stopped: list[str] = Field(default_factory=list)
    already: list[str] = Field(default_factory=list)
    notLocal: list[str] = Field(default_factory=list)
    caseRef: str = ""


class RecoverIn(BaseModel):
    identityHash: str = Field(description="H(ID)，64 位十六进制")

    @field_validator("identityHash")
    @classmethod
    def _hex64(cls, v: str) -> str:
        s = v.strip().lower().removeprefix("0x")
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            raise ValueError("identityHash 必须是 64 位十六进制")
        return s


class RecoverOut(BaseModel):
    did: str
    rebuilt: bool
    cmi: str
    buildDigest: str
    buildDigestChanged: bool = False
    note: str = ""


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = ["RevocationIn", "RevocationOut", "RecoverIn", "RecoverOut", "ErrorOut"]
