"""gateway 的领域模型：收件、应答、出口卡口。

gateway 是 AP 侧**唯一的对外出入口**。它不做业务，只做三件事：

    收件   从跨域通道取回"发给我的"工单
    应答   委托 lifecycle 在本地算，然后把结果送出去
    承接   收到吊销广播，转给 lifecycle 停运

★ 卡口为什么是**白名单**，而通道那头是黑名单：

    coordination 的 `assert_public_material` 用黑名单（键名里带 sk / trapdoor 就拒）。
    它只能这样 —— 因为入站的东西是**别人**写的，形状不可控，
    我们只知道"不该有什么"，没法穷举"该有什么"。

    出站不一样：AP 能提供什么是**我们自己决定的、且有限**的几样东西。
    对自己的输出，就该用白名单 —— 多一个键都说明有人顺手塞了东西。

    同一个系统里两个方向用两种策略，不是不一致，是**按谁可控来定**：
    可控的用白名单，不可控的用黑名单。

★ 三种答复状态为什么都要占用 `answer` 字段：

    "没答" 和 "拒绝答" 必须能被区分开。
    如果一律不回写，工单会挂到过期为止，TP 那边看到的是"没人理" ——
    它会以为是网络问题，于是重开一张，然后撞上限流。
    一个明确的 `refused` 比沉默有用得多。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReplyStatus(str, Enum):
    """答复的三种形态。★ 区别于"没答复"：这三种都会回写工单。"""

    OK = "ok"                   # 查了，给材料
    NOT_LOCAL = "not_local"     # 查了，本机没有这个实例
    REFUSED = "refused"         # 这个请求本身不成立


class GatewayError(RuntimeError):
    """gateway 的拒绝。"""


class ExportBlocked(GatewayError):
    """出口卡口拦下 —— 本方差点把不该出网的东西发出去。

    ★ 这是 gateway 里唯一会**中断且不回写**的拒绝：
      别的拒绝是业务层的（可以告诉对方），这个是安全层的 ——
      一旦回写，等于告诉对岸"我这边有这个字段"，那本身就是信息。
    """


class BadNotice(GatewayError):
    """收到的通知本身不成立（缺字段、缺案由）。"""


class ChannelDown(GatewayError):
    """连不上对岸：整轮都没法开始。

    ★ 与"单张回写失败"是两回事，必须分开：

        连不上        整轮没做，HTTP 上回 503 —— 调用方该等一会儿再来
        单张回写失败  其余照做，本张记 delivered=False，回 200

      合成一个错误，调用方就只能选择"整批重试"（已经答过的会撞上重复答复）
      或"全都当成功"（漏掉的永远没人知道）。
    """


# ★ 出站白名单。AP 侧能给出去的全部就这些。
#   加一种协查类别时，**必须**先想清楚要新增哪个键 —— 这就是白名单的用意：
#   它把"能不能加"变成一次需要解释的改动，而不是顺手加个字段。
#
#   刻意用 frozenset 并公开导出：它是"AP 对外的全部表达能力"，
#   应当可被读取、可被测试钉住，但不该在运行时被某处顺手改掉。
EXPORT_ALLOWED_KEYS = frozenset({
    "status",       # ReplyStatus
    "did",
    "parentDid",
    "agentType",
    "state",
    "phcJson",      # ★ 必须是规范化字符串，不是对象
    "phcDigest",
    "reason",
    "note",
})

_JSON_PRIMITIVES = (str, int, float, bool, type(None))


def assert_exportable(answer: dict) -> None:
    """出口卡口：出网的东西只能是白名单里的标量。

    ★ 即便 lifecycle 已经保证过一次，这里还要再查一遍。
      这不是不信任同事，是不信任**边界本身**：
      lifecycle 是被"内部"信任的服务，而 gateway 是出网的最后一道门。
      一旦 lifecycle 可以直接出网，它的任何一个 bug 都会变成一次外泄。
      门要设在出口上，而不是设在"我猜上游已经查过了"。
    """
    if not isinstance(answer, dict):
        raise ExportBlocked(f"答复必须是对象，收到 {type(answer).__name__}")

    unknown = sorted(set(answer) - EXPORT_ALLOWED_KEYS)
    if unknown:
        raise ExportBlocked(
            f"答复含有未登记的字段 {unknown} —— 出口只放行白名单内的键；"
            "要新增字段必须先在此处登记并说明理由")

    status = str(answer.get("status") or "")
    if status not in {s.value for s in ReplyStatus}:
        raise ExportBlocked(
            f"答复缺少合法的 status（收到 {status!r}）—— "
            "没有状态的答复无法被对岸区分'给了'与'拒绝'")

    for k, v in answer.items():
        if not isinstance(v, _JSON_PRIMITIVES):
            raise ExportBlocked(
                f"字段 {k!r} 的类型 {type(v).__name__} 不是标量 —— "
                "嵌套结构最容易藏东西")
        if isinstance(v, str) and v.startswith("-----BEGIN"):
            raise ExportBlocked(f"字段 {k!r} 疑似 PEM 密钥材料")
        if k == "phcJson" and v and not isinstance(v, str):
            raise ExportBlocked("phcJson 必须是规范化 JSON 字符串，不是对象")


@dataclass(frozen=True)
class InboxTicket:
    """通道里一张待答工单的**本地视图**。

    ★ 刻意不复用 coordination 的 `Ticket` 实体：
      那是对方的内部模型。带上它，换 HTTP 适配器时就要一起序列化对方的实体，
      两边的模型从此绑死。这里只留 gateway 真正需要的四个字段。
    """

    ticket_id: str
    kind: str = ""
    payload: dict = field(default_factory=dict)
    case_ref: str = ""

    @classmethod
    def from_json(cls, d: dict) -> "InboxTicket":
        return cls(ticket_id=d.get("ticketId", ""), kind=d.get("kind", ""),
                   payload=d.get("payload", {}) or {},
                   case_ref=d.get("caseRef", ""))


@dataclass(frozen=True)
class OutboxItem:
    """一张工单的处理结果。

    ★ `delivered` 与 `status` 是两回事：
      delivered=False 表示**没送出网**（被卡口拦下，或回写失败）；
      status=refused 表示送出去了，但内容是一句拒绝。
      前者要报警，后者是正常业务。
    """

    ticket_id: str
    kind: str = ""
    status: str = ""
    delivered: bool = False
    reason: str = ""

    def to_json(self) -> dict:
        return {"ticketId": self.ticket_id, "kind": self.kind,
                "status": self.status, "delivered": self.delivered,
                "reason": self.reason}


@dataclass(frozen=True)
class OutboxReport:
    polled: int = 0
    items: list[OutboxItem] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)     # 被卡口拦下的单号

    @property
    def answered(self) -> int:
        return sum(1 for i in self.items if i.delivered)

    def to_json(self) -> dict:
        return {"polled": self.polled, "answered": self.answered,
                "blocked": list(self.blocked),
                "items": [i.to_json() for i in self.items]}


@dataclass(frozen=True)
class IntakeResult:
    """承接一条吊销广播的结果。"""

    root_did: str
    stopped: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    not_local: list[str] = field(default_factory=list)
    case_ref: str = ""
    accepted: bool = True
    reason: str = ""

    def to_json(self) -> dict:
        return {"rootDid": self.root_did, "accepted": self.accepted,
                "stopped": list(self.stopped), "already": list(self.already),
                "notLocal": list(self.not_local), "caseRef": self.case_ref,
                "reason": self.reason}


__all__ = [
    "ReplyStatus", "GatewayError", "ExportBlocked", "BadNotice", "ChannelDown",
    "assert_exportable", "EXPORT_ALLOWED_KEYS",
    "InboxTicket", "OutboxItem", "OutboxReport", "IntakeResult",
]
