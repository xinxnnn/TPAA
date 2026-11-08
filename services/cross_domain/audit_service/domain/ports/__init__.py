"""audit-service 的端口。

★ 注意这里**没有 AuditSink**：审计服务是别人的 sink，自己不该再有 sink。
  一条审计记录如果要"再记到别处一遍"，那两处迟早会不一致，
  而不一致的那一刻，你无法判断哪一份才是真的。所以它只写自己的账。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str: ...


@runtime_checkable
class LedgerPort(Protocol):
    def append(self, entry): ...
    def all(self) -> list: ...
    def get(self, entry_id: str): ...
    def tail(self): ...
    def self_check(self) -> None: ...


@runtime_checkable
class AttestSink(Protocol):
    """子体 PHC 存证的去处。

    PHC 本体可能较大，也可能含 ECID（加密后的 CID）。
    审计链记录的是**指纹 + 必要字段**，原文是否另存由实现决定 ——
    但"存过证"这件事必须在链上留下不可否认的一笔。
    """

    def put(self, *, did: str, phc_json: dict) -> str:
        """返回附件编号。"""
        ...


__all__ = ["Clock", "LedgerPort", "AttestSink"]
