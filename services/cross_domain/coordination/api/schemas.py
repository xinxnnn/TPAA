"""coordination 的 HTTP 契约。

载荷字段一律用 `dict`：通道不该认识业务字段名，
它的职责是"这堆东西能不能过界"，不是"这堆东西是什么意思"。
一旦它开始认识字段，加一种协查就要改通道 —— 而通道恰好是最不该频繁改的地方。
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class OpenIn(BaseModel):
    requester: str = Field(min_length=1, description="TP 或 AP")
    responder: str = Field(min_length=1, description="TP 或 AP，且不能与 requester 相同")
    kind: str = Field(min_length=1, description="协查类别，例如 random_factor")
    payload: dict = Field(default_factory=dict)
    caseRef: str = ""
    ttlHours: int = 72


class OpenOut(BaseModel):
    ticketId: str
    requester: str
    responder: str
    kind: str
    state: str
    createdAt: str
    caseRef: str = ""


class AnswerIn(BaseModel):
    responder: str = Field(min_length=1)
    answer: dict = Field(default_factory=dict)


class AnswerOut(BaseModel):
    ticketId: str
    state: str
    answeredAt: str


class TicketOut(BaseModel):
    ticketId: str
    requester: str
    responder: str
    kind: str
    payload: dict = Field(default_factory=dict)
    state: str
    createdAt: str
    answeredAt: str = ""
    answer: dict = Field(default_factory=dict)
    caseRef: str = ""


class ListOut(BaseModel):
    """收件箱。★ 只含发给 responder 自己的单子 —— 见 usecases/list_tickets。"""

    responder: str
    state: str = ""
    count: int = 0
    tickets: list[TicketOut] = Field(default_factory=list)


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = ["OpenIn", "OpenOut", "AnswerIn", "AnswerOut", "TicketOut", "ListOut",
           "ErrorOut"]
