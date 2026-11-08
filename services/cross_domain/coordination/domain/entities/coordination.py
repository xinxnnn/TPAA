"""coordination 的领域模型：协查工单。

★ 它存在的唯一理由：TP 区与 AP 区之间**默认拒绝直连**（§10 网络策略）。
    所以两边要说任何话，都得经过这里留一张工单。
    这不是官僚 —— 追溯时能不能说清"TP 到底问过 AP 什么"，全靠这张单子。

★ 为什么工单内容要过卡口：
    通道是双向的，但**能力不是**。TP 有权要随机因子，无权要 AP 的陷门；
    AP 有权要 TP 的公钥，无权要 TP 的私钥。
    两边都是自己人，所以这不能靠"大家都自觉" —— 要靠一个不认识任何一边的函数
    把 payload 翻一遍。见 `assert_public_material`。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TicketState(str, Enum):
    PENDING = "pending"
    ANSWERED = "answered"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ChannelError(RuntimeError):
    """通道层的拒绝。"""


class RateLimited(ChannelError):
    """限流。刻意独立成一个类型：调用方要据此决定"等一会儿再来"，
    而"参数填错"再等也没用 —— 两者不该共用同一个错误码。"""


class NonPublicPayload(ChannelError):
    """载荷里出现了不该跨域的东西。"""


# ★ 键名黑名单。命中即拒。
#   这不是为了防攻击者（攻击者会改名），而是为了防**自己人图省事**：
#   把一个对象塞进 payload 时，键名通常还叫 sk / trapdoor —— 卡口要在这个瞬间拦住。
_FORBIDDEN_KEYS = {
    "sk", "privatekey", "private_key", "trapdoor", "secret", "seed",
    "schnorr_sk", "chameleon_sk", "priv", "privatekey_hex", "keymaterial",
    "cscid",          # 加密身份标识：跨域传递等于把钥匙胚到处复制
    "identityhash",   # H(ID) 明文：TP 已经知道，AP 侧不需要再收一次
}

# 允许跨域的载荷值类型：只能是这些。出现别的类型说明有人塞了对象。
_JSON_PRIMITIVES = (str, int, float, bool, type(None))


def assert_public_material(payload: dict) -> None:
    """卡口：payload 只能是扁平的公开材料。

    ★ 拒绝嵌套 dict —— 扁平化本身就是一种约束：
      嵌套结构最容易藏东西，而协查真正要传的从来只是几个标量
      （一个随机数、一个 CID、一个时间戳）。
    """
    if payload is None:
        return
    if not isinstance(payload, dict):
        raise NonPublicPayload("协查载荷必须是对象")

    for k, v in payload.items():
        flat = str(k).strip().lower().replace("-", "").replace("_", "")
        if flat in _FORBIDDEN_KEYS:
            raise NonPublicPayload(
                f"载荷字段 {k!r} 属于不得跨域传递的内容 —— 通道只传公开材料")
        if not isinstance(v, _JSON_PRIMITIVES):
            raise NonPublicPayload(
                f"载荷字段 {k!r} 的类型 {type(v).__name__} 不是标量 —— "
                "协查只传标量，对象容易被顺手塞进密钥句柄")
        if isinstance(v, str) and v.startswith("-----BEGIN"):
            raise NonPublicPayload(f"载荷字段 {k!r} 疑似 PEM 密钥材料")


@dataclass
class Ticket:
    """一张协查工单。"""

    ticket_id: str
    requester: str                  # TP / AP
    responder: str                  # 对方
    kind: str                       # random_factor / pubkey / lineage_proof ...
    payload: dict = field(default_factory=dict)
    state: TicketState = TicketState.PENDING
    created_at: str = ""
    answered_at: str = ""
    answer: dict = field(default_factory=dict)
    case_ref: str = ""              # 关联的立案编号；为空即"无案由的询问"
    ttl_hours: int = 72

    def to_json(self) -> dict:
        return {
            "ticketId": self.ticket_id,
            "requester": self.requester,
            "responder": self.responder,
            "kind": self.kind,
            "payload": self.payload,
            "state": self.state.value,
            "createdAt": self.created_at,
            "answeredAt": self.answered_at,
            "answer": self.answer,
            "caseRef": self.case_ref,
            "ttlHours": self.ttl_hours,
        }

    @classmethod
    def from_json(cls, d: dict) -> "Ticket":
        return cls(
            ticket_id=d.get("ticketId", ""),
            requester=d.get("requester", ""),
            responder=d.get("responder", ""),
            kind=d.get("kind", ""),
            payload=d.get("payload", {}) or {},
            state=TicketState(d.get("state", "pending")),
            created_at=d.get("createdAt", ""),
            answered_at=d.get("answeredAt", ""),
            answer=d.get("answer", {}) or {},
            case_ref=d.get("caseRef", ""),
            ttl_hours=int(d.get("ttlHours", 72)),
        )

    def answer_with(self, answer: dict, *, at: str) -> None:
        assert_public_material(answer)
        self.answer = dict(answer)
        self.answered_at = at
        self.state = TicketState.ANSWERED


__all__ = [
    "Ticket", "TicketState", "ChannelError", "RateLimited", "NonPublicPayload",
    "assert_public_material",
]
