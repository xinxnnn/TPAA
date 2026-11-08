"""policy-service 的端口。

三个动作，对应吊销的三段：

    DirectoryPort.revoke_with_cascade   先把"谁是后代"这件事交给掌握事实的一方
    NotifyPort.notify_revoked           再让 AP 侧把实例停掉
    AuditSink.append                    最后留痕

★ 顺序是刻意的：**先吊销，后停运**。
  反过来做，中间失败就会出现"实例停了但凭证还有效"——
  用户拿着一个有效凭证却跑不起来，会来投诉，然后运维手动恢复实例，
  于是吊销悄悄失效了。先吊销，最坏情况是"凭证已废但实例还在跑最后几秒"，
  那是个可以补救的窗口。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class CascadeResult:
    root: str = ""
    revoked: list[str] = field(default_factory=list)
    already_revoked: list[str] = field(default_factory=list)


@runtime_checkable
class DirectoryPort(Protocol):
    def revoke_with_cascade(self, did: str, *, reason: str,
                            by: str) -> CascadeResult: ...


@runtime_checkable
class NotifyPort(Protocol):
    def notify_revoked(self, *, root_did: str, revoked: list[str],
                       case_ref: str, reason: str) -> list[str]:
        """让 AP 侧停止这些实例。返回实际被停运的 DID。"""
        ...


@runtime_checkable
class AuditSink(Protocol):
    def append(self, *, kind: str, subject: str, payload: dict) -> str: ...

    def probe(self) -> tuple[bool, str]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str: ...


@runtime_checkable
class OrderStore(Protocol):
    def put(self, order) -> None: ...
    def get(self, order_id: str): ...
    def all(self) -> dict: ...
    def self_check(self) -> None: ...


__all__ = ["CascadeResult", "DirectoryPort", "NotifyPort", "AuditSink", "Clock",
           "OrderStore"]
