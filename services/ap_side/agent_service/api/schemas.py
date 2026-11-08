"""HTTP 契约（Pydantic 模型）—— 只描述"线路上长什么样"，不含业务规则。

一处刻意的取舍：`identityHash` 接收十六进制字符串，**不接收 int**。
    理由：它是一个 256 位整数，JSON 的 number 在很多语言里是 float64，
    超过 2^53 就会被静默截断 —— 而截断后的哈希依然"看起来像个数"，
    会让所有身份悄悄变成同一个人。十六进制字符串没有这个陷阱。
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ModuleChoiceIn(BaseModel):
    moduleId: str = Field(min_length=1)
    version: str = Field(min_length=1)


class SelectionIn(BaseModel):
    items: list[ModuleChoiceIn] = Field(min_length=1)


class IssueIn(BaseModel):
    identityHash: str = Field(description="H(ID)，64 位十六进制（不带 0x）")
    selection: SelectionIn
    ttlDays: int = 0

    @field_validator("identityHash")
    @classmethod
    def _hex64(cls, v: str) -> str:
        s = v.strip().lower().removeprefix("0x")
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            raise ValueError("identityHash 必须是 64 位十六进制")
        if int(s, 16) == 0:
            raise ValueError("identityHash 不能为 0")
        return s


class IssueOut(BaseModel):
    did: str
    cmi: str
    buildDigest: str
    layers: list[str] = Field(default_factory=list)
    keptExisting: bool = False
    phc: dict


class PrepareIn(BaseModel):
    parentDid: str = Field(min_length=1)
    selection: SelectionIn
    ttlHours: int = 720


class PrepareOut(BaseModel):
    ticketId: str
    parentDid: str
    selectionDigest: str
    ttlHours: int
    createdAt: str
    # 用户界面要展示给人看的那句话：确认的是什么，不是"确认一下"四个字
    summary: str


class ConfirmIn(BaseModel):
    ticketId: str
    parentDid: str
    selection: SelectionIn
    ttlHours: int
    # ★ 用户在确认界面上看到的那份方案摘要，必须原样回传。
    #   服务端拿它和自己重算的比，比不一致就是"你确认的不是这份方案"。
    #   没有这个字段时，confirm 等于自己给自己发令牌 —— 闸门形同虚设。
    selectionDigest: str = Field(min_length=64, max_length=64)
    confirmedBy: str = Field(default="user", min_length=1)


class ConfirmOut(BaseModel):
    token: str
    selectionDigest: str
    confirmedAt: str


class DeriveIn(BaseModel):
    parentDid: str
    selection: SelectionIn
    ttlHours: int
    # ★ 必填、且没有默认值：缺令牌就是"没确认"，不允许退化成"先派生再说"
    confirmToken: str | None = None


class DeriveOut(BaseModel):
    did: str
    parentDid: str
    cmi: str
    expiresAt: str
    buildDigest: str
    phc: dict


class RecoverIn(BaseModel):
    identityHash: str
    did: str = Field(min_length=1)

    @field_validator("identityHash")
    @classmethod
    def _hex64(cls, v: str) -> str:
        s = v.strip().lower().removeprefix("0x")
        if len(s) != 64:
            raise ValueError("identityHash 必须是 64 位十六进制")
        return s


class RecoverOut(BaseModel):
    did: str
    rebuilt: bool
    cmi: str
    buildDigest: str
    buildDigestChanged: bool = False
    note: str = ""


class LocateOut(BaseModel):
    items: list[dict]


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = [
    "ModuleChoiceIn", "SelectionIn", "IssueIn", "IssueOut",
    "PrepareIn", "PrepareOut", "ConfirmIn", "ConfirmOut",
    "DeriveIn", "DeriveOut", "RecoverIn", "RecoverOut", "LocateOut", "ErrorOut",
]
