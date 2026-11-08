"""supervision-service 依赖外部什么。

四个端口，每一个都对应协议里一句话：

    DirectoryPort   问 did-service：这个 DID 是谁家的、往上是谁、密文在哪
                    └ 追溯的"归属"靠它
    ChannelPort     经 coordination 问 AP 要归属证明
                    └ 追溯的"协查"靠它
    StoragePort     凭 ECID 从 IPFS 取回信封
                    └ 取证 R2 靠它
    AuditSink       往审计链写一笔
                    └ 事后能举证靠它

★ 这里同样**没有任何返回密钥的方法**。
  唯一能"打开身份"的东西是构造时注入的监管密钥句柄，
  它不是一个端口 —— 端口是可以被替换的，而"谁能还原身份"不该可替换。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class DidView:
    """did-service 给出的公开视图。注意：没有 H(ID)，没有 CSCID。"""

    did: str
    parent_did: str = ""
    agent_type: str = "primary"
    state: str = "active"
    ecid_ref: str = ""


@dataclass(frozen=True)
class LineageView:
    chain: list[str] = field(default_factory=list)
    root: str = ""
    depth: int = 0


@dataclass(frozen=True)
class TicketView:
    ticket_id: str
    state: str
    answer: dict = field(default_factory=dict)


@runtime_checkable
class DirectoryPort(Protocol):
    def resolve(self, did: str) -> DidView: ...

    def reveal_cscid(self, did: str, *, case_ref: str,
                     requested_by: str) -> str: ...

    def trace(self, did: str) -> LineageView: ...


@runtime_checkable
class ChannelPort(Protocol):
    def open(self, *, requester: str, responder: str, kind: str,
             payload: dict, case_ref: str) -> str:
        """返回工单号。"""
        ...

    def get(self, ticket_id: str) -> TicketView: ...


@runtime_checkable
class StoragePort(Protocol):
    def fetch_by_ecid(self, ecid: str) -> bytes:
        """ECID → CID → 密文。CID 在服务内部还原，不落库、不外传（红线 17）。"""
        ...


@runtime_checkable
class AuditSink(Protocol):
    def append(self, *, kind: str, subject: str, payload: dict) -> str: ...

    def probe(self) -> tuple[bool, str]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str: ...


__all__ = ["DidView", "LineageView", "TicketView", "DirectoryPort", "ChannelPort",
           "StoragePort", "AuditSink", "Clock"]
