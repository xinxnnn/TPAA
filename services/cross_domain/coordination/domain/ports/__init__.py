"""coordination 的端口。

跨域通道自己也需要一个"归档地"：工单一经创建就不可改、不可删，
否则"TP 问过什么"这句话就失去了证据价值。所以这里声明了一个 AuditSink ——
coordination 自己不实现审计链（那是 audit-service 的事），
它只要求"有一个地方能追加一条记录"。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str:
        """ISO 8601 时间戳（秒级）。"""
        ...

    def plus_hours(self, hours: int) -> str: ...


@runtime_checkable
class TicketStore(Protocol):
    def get(self, ticket_id: str): ...
    def put(self, ticket) -> None: ...
    def all(self) -> dict: ...
    def self_check(self) -> None: ...


@runtime_checkable
class AuditSink(Protocol):
    """审计归档。可以为 NotImplementedAudit —— 那时通道仍然可用，只是不留痕。"""

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        """追加一条，返回记录号。"""
        ...


__all__ = ["Clock", "TicketStore", "AuditSink"]
