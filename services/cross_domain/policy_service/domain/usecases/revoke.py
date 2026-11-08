"""按令吊销，并按 parent_did 级联。

三段式，每一段的失败处理都不一样 —— 这正是它值得单独成一个用例的原因：

    第 1 段 撤销（did-service）失败 → 整条令记为 failed，**不通知 AP**
             理由：凭证还在有效状态就把实例停了，会造成"有效凭证跑不动"的怪状态。
    第 2 段 通知（AP）失败       → 令停在 cascaded，由重试补齐
             理由：吊销本身已经生效，AP 侧晚一点停运是可接受的降级。
    第 3 段 留痕失败             → 抛。没留痕的吊销等于没发生过。

★ 幂等：同一条令重复执行，第二次会得到 already_revoked 而不是报错。
  追溯时人会在慌乱中重复点按钮，系统不该因此记两条。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..entities import MissingGrounds, OrderState, RevocationOrder


@dataclass(frozen=True)
class RevokeCommand:
    root_did: str
    case_ref: str
    reason: str
    issued_by: str = ""


@dataclass(frozen=True)
class RevokeOutcome:
    order_id: str
    state: str
    revoked: list[str]
    already_revoked: list[str]
    notified: list[str]
    failure: str = ""


class RevokeUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RevokeCommand) -> RevokeOutcome:
        if not cmd.root_did.strip():
            raise MissingGrounds("吊销令必须指明 DID")
        if not cmd.case_ref.strip():
            raise MissingGrounds(
                "吊销令必须写明案由 —— 没有案由的吊销，事后无法解释是谁为什么关掉了谁")
        if not cmd.reason.strip():
            raise MissingGrounds("吊销令必须写明理由")

        now = self.ctx.clock.now()
        order = RevocationOrder(
            order_id="ord-" + hashlib.sha256(
                f"{cmd.root_did}|{cmd.case_ref}|{now}".encode()).hexdigest()[:16],
            root_did=cmd.root_did, case_ref=cmd.case_ref, reason=cmd.reason,
            issued_by=cmd.issued_by, issued_at=now,
        )

        # 第 1 段：撤销 + 级联
        try:
            res = self.ctx.directory.revoke_with_cascade(
                cmd.root_did, reason=cmd.reason, by=cmd.issued_by)
        except Exception as exc:                     # noqa: BLE001
            order.state = OrderState.FAILED
            order.failure = f"撤销失败，未通知 AP：{exc}"
            self.ctx.orders.put(order)
            self._audit(order)
            raise

        order.revoked = list(res.revoked)
        order.already = list(res.already_revoked)
        order.state = OrderState.CASCADED
        self.ctx.orders.put(order)
        self._audit(order)

        # 第 2 段：通知 AP 停运
        try:
            order.notified = list(self.ctx.notify.notify_revoked(
                root_did=cmd.root_did, revoked=order.revoked,
                case_ref=cmd.case_ref, reason=cmd.reason))
            order.state = OrderState.NOTIFIED
        except Exception as exc:                     # noqa: BLE001
            # 吊销已生效，通知没送到 —— 记下来，等重试；不把整条令判死
            order.failure = f"已撤销但通知 AP 失败（待重试）：{exc}"

        self.ctx.orders.put(order)
        self._audit(order)
        return RevokeOutcome(
            order_id=order.order_id, state=order.state.value,
            revoked=order.revoked, already_revoked=order.already,
            notified=order.notified, failure=order.failure)

    # ------------------------------------------------------------------

    def _audit(self, order: RevocationOrder) -> None:
        self.ctx.audit.append(
            kind="policy.revoked", subject=order.order_id,
            payload={"caseRef": order.case_ref, "rootDid": order.root_did,
                     "state": order.state.value, "revoked": order.revoked,
                     "notified": order.notified, "reason": order.reason,
                     "issuedBy": order.issued_by})


class ResendNoticeUseCase:
    """重发通知 —— 第 2 段失败后的补齐路径。"""

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, order_id: str) -> RevokeOutcome:
        order = self.ctx.orders.get(order_id)
        if order is None:
            raise ValueError(f"吊销令 {order_id} 不存在")
        if order.state is OrderState.NOTIFIED:
            return RevokeOutcome(order_id=order.order_id, state=order.state.value,
                                 revoked=order.revoked, already_revoked=order.already,
                                 notified=order.notified)

        order.notified = list(self.ctx.notify.notify_revoked(
            root_did=order.root_did, revoked=order.revoked,
            case_ref=order.case_ref, reason=order.reason))
        order.state = OrderState.NOTIFIED
        order.failure = ""
        self.ctx.orders.put(order)
        self._audit(order)
        return RevokeOutcome(order_id=order.order_id, state=order.state.value,
                             revoked=order.revoked, already_revoked=order.already,
                             notified=order.notified)

    def _audit(self, order: RevocationOrder) -> None:
        self.ctx.audit.append(
            kind="policy.notice_resent", subject=order.order_id,
            payload={"caseRef": order.case_ref, "rootDid": order.root_did,
                     "notified": order.notified})


__all__ = ["RevokeUseCase", "RevokeCommand", "RevokeOutcome", "ResendNoticeUseCase"]
