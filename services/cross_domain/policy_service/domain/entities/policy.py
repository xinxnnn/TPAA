"""吊销令与吊销结果。

一条吊销令必须回答三个问题：吊销谁、为什么、依据哪份案卷。
少任何一个，这条令在事后都无法被解释 —— 而吊销是不可逆的。

★ 为什么 `case_ref` 是必填而不是可选：
  允许"没有案由的吊销"，等于允许平台在没有立案的情况下关停任何人的智能体。
  这条口子一旦留着，迟早会被用来做别的事。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OrderState(str, Enum):
    ISSUED = "issued"          # 已下令，尚未执行
    CASCADED = "cascaded"      # 已按 parent_did 展开并撤销
    NOTIFIED = "notified"      # 已通知 AP 侧停运
    FAILED = "failed"          # 中途失败（下游不可达）


class PolicyError(RuntimeError):
    """策略层的拒绝。"""


class MissingGrounds(PolicyError):
    """缺案由 / 缺理由。语义是"这条令站不住"，不是"系统坏了"。"""


@dataclass
class RevocationOrder:
    order_id: str
    root_did: str
    case_ref: str
    reason: str
    issued_by: str = ""
    issued_at: str = ""
    state: OrderState = OrderState.ISSUED
    revoked: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    notified: list[str] = field(default_factory=list)
    failure: str = ""

    def to_json(self) -> dict:
        return {
            "orderId": self.order_id, "rootDid": self.root_did,
            "caseRef": self.case_ref, "reason": self.reason,
            "issuedBy": self.issued_by, "issuedAt": self.issued_at,
            "state": self.state.value, "revoked": self.revoked,
            "alreadyRevoked": self.already, "notified": self.notified,
            "failure": self.failure,
        }

    @classmethod
    def from_json(cls, d: dict) -> "RevocationOrder":
        return cls(
            order_id=d.get("orderId", ""), root_did=d.get("rootDid", ""),
            case_ref=d.get("caseRef", ""), reason=d.get("reason", ""),
            issued_by=d.get("issuedBy", ""), issued_at=d.get("issuedAt", ""),
            state=OrderState(d.get("state", "issued")),
            revoked=list(d.get("revoked", [])),
            already=list(d.get("alreadyRevoked", [])),
            notified=list(d.get("notified", [])),
            failure=d.get("failure", ""),
        )


__all__ = ["RevocationOrder", "OrderState", "PolicyError", "MissingGrounds"]
