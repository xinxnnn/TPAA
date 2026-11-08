"""列出待我答复的工单（收件箱）。

★ 为什么这个端点必须**强制 responder 过滤**：

    通道是 TP 与 AP 共用的。一个不带过滤的 `GET /v1/tickets` 会让任何一方
    看到全网所有跨域询问 —— 包括发给别的节点的、与它无关的。
    "谁在查谁"本身就是敏感信息：它能画出一张"监管正在盯哪些 DID"的图。

    所以这里不做"不给过滤条件就返回全部"的兜底，而是直接拒绝。
    默认拒绝的意思就是：没说清楚要哪一份，就一份也不给。

★ 为什么过期工单**不返回**而不只是标一下：
    答一张 72 小时前的单子没有意义 —— 那边的案件可能已经结了，
    而 AP 侧的归属关系在这期间可能已经变了（子体被吊销、实例被找回）。
    给它一份"现在看起来对、但当时不是那样"的答案，比不给更糟。

    过期判定是**读时算的**，不写盘、不改状态。
    改状态要落一次盘，而"谁在什么时候列了一次收件箱"不该有写副作用 ——
    否则 TP 只要反复列，就能把 AP 的工单全刷成 expired。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..entities import Ticket, TicketState


_PARTIES = {"TP", "AP"}
_TIME_FMT = "%Y-%m-%dT%H:%M:%S"


class ListError(RuntimeError):
    """收件箱查询被拒。"""


@dataclass(frozen=True)
class ListCommand:
    responder: str
    state: str = TicketState.PENDING.value
    case_ref: str = ""
    limit: int = 100


class ListTicketsUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: ListCommand) -> list[Ticket]:
        who = (cmd.responder or "").strip().upper()
        if who not in _PARTIES:
            raise ListError(
                f"responder 必须是 TP 或 AP，收到 {cmd.responder!r} —— "
                "收件箱不接受不带过滤的查询")

        want_state = (cmd.state or "").strip().lower()
        if want_state:
            try:
                TicketState(want_state)
            except ValueError as exc:
                raise ListError(f"未知的工单状态 {want_state!r}") from exc

        now = self.ctx.clock.now()
        out: list[Ticket] = []
        for t in self.ctx.tickets.all().values():
            if t.responder != who:
                continue
            if want_state and t.state.value != want_state:
                continue
            if cmd.case_ref and t.case_ref != cmd.case_ref:
                continue
            if _is_expired(t, now):
                continue
            out.append(t)

        # 老单在前：先来先答，避免后到的单子被反复插队饿死
        out.sort(key=lambda t: t.created_at)
        if cmd.limit > 0:
            out = out[: cmd.limit]
        return out


def _is_expired(t: Ticket, now: str) -> bool:
    """读时判定过期。

    ★ 时间解析失败时**按未过期处理**：
      时钟格式不一致是配置问题，把它当成"过期"会静默吞掉一批待办，
      而当成"未过期"最多是多答一单 —— 两种错法的代价不对等。
    """
    try:
        created = datetime.strptime(t.created_at, _TIME_FMT)
        cur = datetime.strptime(now, _TIME_FMT)
    except (ValueError, TypeError):
        return False
    return cur - created > timedelta(hours=max(int(t.ttl_hours or 0), 0))


__all__ = ["ListTicketsUseCase", "ListCommand", "ListError", "Ticket"]
