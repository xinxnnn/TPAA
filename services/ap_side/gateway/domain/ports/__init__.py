"""gateway 依赖外部什么。

    ChannelPort   跨域通道（coordination）—— 收件与回写都走它
    AssistPort    本地算答案（lifecycle-service）
    StopPort      本地停运（lifecycle-service）
    AuditSink     留痕
    Clock         时间

★ 三个端口，三种替换时机：

    ChannelPort   分区部署时**第一个**要被换成 HTTP 客户端的。
                  它跨了安全域，是唯一真正需要走网络的一个。
    AssistPort    通常与 gateway 同机（都在 AP 侧），保持进程内调用即可。
    StopPort      同上。

★ 为什么把 Assist 与 Stop 分成两个端口而不是合成一个 "LifecyclePort"：
  它们的可替换性不同。真要做异地多活时，停运必须打到**实例所在的那个节点**，
  而协查应答打到任意一个持有该实例的节点都行。
  合成一个端口，就等于替未来做了一个现在没理由做的决定。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@runtime_checkable
class ChannelPort(Protocol):
    def pull(self, *, responder: str, state: str = "pending",
             limit: int = 100) -> list:
        """取回发给 responder 的待答工单，返回 InboxTicket 列表。"""
        ...

    def answer(self, *, ticket_id: str, responder: str,
               answer: dict) -> dict:
        """回写答复。返回 dict（至少含 state）。"""
        ...


@runtime_checkable
class AssistPort(Protocol):
    def answer_assist(self, *, kind: str, payload: dict) -> dict:
        """在本地算协查答复。抛异常表示"答不了"。

        ★ 返回的是**待出网**的字典，还没过出口卡口 ——
          卡口在 gateway 这一侧，不在生产答案的那一侧。
        """
        ...


@dataclass(frozen=True)
class StopOutcome:
    stopped: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    not_local: list[str] = field(default_factory=list)


@runtime_checkable
class StopPort(Protocol):
    def stop(self, *, root_did: str, revoked: list[str], case_ref: str,
             reason: str) -> StopOutcome:
        """把本地实例停掉（冻结，不是删除）。"""
        ...


@runtime_checkable
class AuditSink(Protocol):
    def append(self, *, kind: str, subject: str, payload: dict) -> str: ...

    def probe(self) -> tuple[bool, str]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str: ...


__all__ = ["ChannelPort", "AssistPort", "StopPort", "StopOutcome", "AuditSink",
           "Clock"]
