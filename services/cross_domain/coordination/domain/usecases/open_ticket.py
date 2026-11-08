"""开一张协查工单。

四道检查，顺序不能换：

    1  方向    requester / responder 必须是 TP 与 AP 之间的**一对**，不能同向自己
    2  载荷    过 assert_public_material —— 卡在入库之前
    3  配额    过限流 —— 卡在写盘之前
    4  留痕    写盘之后立刻归档

为什么留痕排在写盘之后：
    先记账后干活，账上会出现"发生了但没落地"的条目；
    先干活后记账，账上永远只会少记，不会多记。取证时前者更难解释。

★ 工单一旦创建就不可改内容：payload 只有创建那一次写入机会。
  事后要证明"这张单子没被改过"，靠的是 audit-service 的哈希链，
  而不是单号本身 —— 单号只保证唯一，证明力在链上。
"""

from __future__ import annotations

import hashlib
import secrets

from ..entities import NonPublicPayload, Ticket, assert_public_material


_PARTIES = {"TP", "AP"}


class OpenTicketUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, requester: str, responder: str, kind: str,
                payload: dict | None = None, case_ref: str = "",
                ttl_hours: int = 72) -> Ticket:
        requester = requester.strip().upper()
        responder = responder.strip().upper()
        if requester not in _PARTIES or responder not in _PARTIES:
            raise ValueError("协查只在 TP 与 AP 之间发生")
        if requester == responder:
            raise ValueError("requester 与 responder 不能是同一方")
        if not kind.strip():
            raise ValueError("工单必须写明 kind —— 空白类别无法审计")

        payload = dict(payload or {})
        assert_public_material(payload)

        now = self.ctx.clock.now()
        existing = self.ctx.tickets.all()
        self.ctx.limiter.check(requester=requester, tickets=existing,
                               case_ref=case_ref, now=now)

        ticket_id = ("tk-" + _digest(requester, responder, kind, payload, now)[:16]
                     + "-" + secrets.token_hex(3))
        ticket = Ticket(
            ticket_id=ticket_id, requester=requester, responder=responder,
            kind=kind, payload=payload, created_at=now,
            case_ref=case_ref, ttl_hours=ttl_hours,
        )
        self.ctx.tickets.put(ticket)

        # 留痕：把"谁问了谁、问了什么类别"记进审计链
        self.ctx.audit.append(
            kind="coordination.request", subject=ticket_id,
            payload={"requester": requester, "responder": responder,
                     "kindRequested": kind, "caseRef": case_ref},
        )
        return ticket


def _digest(*parts) -> str:
    h = hashlib.sha256()
    h.update(repr(parts).encode())
    return h.hexdigest()


__all__ = ["OpenTicketUseCase", "NonPublicPayload"]
