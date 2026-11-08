"""gateway 的 HTTP 契约。

★ 入站模型刻意**很瘦**：
   收件箱轮询不需要入参（本方身份是装配时定的，不是请求里带的），
   承接吊销才需要四个字段。
   "谁在调用"不该由请求体决定 —— 否则任何人都能说自己是 AP。
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DrainIn(BaseModel):
    limit: int = Field(default=0, ge=0, le=500,
                       description="0 表示用装配时配置的 batch_limit")


class ItemOut(BaseModel):
    ticketId: str
    kind: str = ""
    status: str = ""
    delivered: bool = False
    reason: str = ""


class DrainOut(BaseModel):
    polled: int = 0
    answered: int = 0
    blocked: list[str] = Field(default_factory=list)
    items: list[ItemOut] = Field(default_factory=list)


class RevocationIn(BaseModel):
    rootDid: str = Field(min_length=1)
    revoked: list[str] = Field(default_factory=list)
    # ★ 必填：广播来自网络，边界上再查一次
    caseRef: str = Field(min_length=1)
    reason: str = ""


class RevocationOut(BaseModel):
    rootDid: str
    accepted: bool = True
    stopped: list[str] = Field(default_factory=list)
    already: list[str] = Field(default_factory=list)
    notLocal: list[str] = Field(default_factory=list)
    caseRef: str = ""
    reason: str = ""


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = ["DrainIn", "DrainOut", "ItemOut", "RevocationIn", "RevocationOut",
           "ErrorOut"]
