"""答复工单。

三条规矩：

1. **只有 responder 能答复**。TP 开的单子只有 AP 能答 —— 否则 TP 可以自问自答，
   通道就成了"自己给自己出证明"。
2. **只能答一次**。已答复的单不能再答：重复答复会让取证时无法确定哪一份是真的。
3. **答复内容同样过卡口**。入口卡了、出口不卡，等于没卡 ——
   这正是很多通道在实战里被打穿的方式。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import ChannelError, Ticket, TicketState


class TicketNotFound(ChannelError):
    pass


@dataclass(frozen=True)
class AnswerResult:
    ticket_id: str
    state: str
    answered_at: str


class AnswerTicketUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, ticket_id: str, responder: str,
                answer: dict) -> AnswerResult:
        ticket = self.ctx.tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFound(f"工单 {ticket_id} 不存在")

        who = responder.strip().upper()
        if who != ticket.responder:
            raise ChannelError(
                f"工单由 {ticket.requester} 发起，只有 {ticket.responder} 能答复；"
                f"{who} 无权代答")
        if ticket.state is not TicketState.PENDING:
            raise ChannelError(
                f"工单已处于 {ticket.state.value}，不能重复答复 —— "
                "取证时无法区分哪一份才是真的")

        now = self.ctx.clock.now()
        ticket.answer_with(dict(answer or {}), at=now)   # 内部会过卡口
        self.ctx.tickets.put(ticket)

        self.ctx.audit.append(
            kind="coordination.response", subject=ticket_id,
            payload={"responder": who, "kindRequested": ticket.kind,
                     "caseRef": ticket.case_ref},
        )
        return AnswerResult(ticket_id=ticket_id, state=ticket.state.value,
                            answered_at=now)


class GetTicketUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, ticket_id: str) -> Ticket:
        t = self.ctx.tickets.get(ticket_id)
        if t is None:
            raise TicketNotFound(f"工单 {ticket_id} 不存在")
        return t


__all__ = ["AnswerTicketUseCase", "AnswerResult", "GetTicketUseCase",
           "TicketNotFound"]
