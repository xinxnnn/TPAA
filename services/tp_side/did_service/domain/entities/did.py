"""DID 注册表的领域模型。

这里只回答三个问题：这个 DID 存在吗、它的父亲是谁、它还有效吗。
**密钥一个字都没有** —— did-service 是"号码簿"，不是"签发者"：
DID 的值由 phc-service 用算法2 算出来，did-service 只负责确认它没被用过、并记住关系。

★ CSCID 为什么存在这里（与 §六 服务总表的一处落地差异）：
    总表给 did-service 的职责是"DID 生成、解析、撤销列表、parent_did 索引"，
    没有提封存。但落地时发现：**DID 登记是 TP 侧第一次拿到 H(ID) 的时刻**，
    封存必须就在这一刻完成 —— 晚一步，明文就已经在别处留过痕了。
    所以这里把 `cscid` 一并登记，但存的是**监管公钥加密后的密文**，
    明文不落盘、也不出现在任何响应里。did-service 依然不持任何私钥。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DidState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class RegistryError(RuntimeError):
    """注册表层的拒绝。语义都是"这件事不能这么做"，而不是"系统坏了"。 """


class DuplicateDid(RegistryError):
    """DID 重复 —— 唯一性是派生链能上溯的前提，重复即全盘不可信。"""


class UnknownDid(RegistryError):
    """查不到。对外是 404，不是 400：调用方没做错，是这个号确实不存在。"""


@dataclass
class DidRecord:
    """一条注册记录。

    `parent_did` 为空串即"主智能体"，非空即"派生子体"。
    这个字段是级联吊销的唯一依据 —— 所以它在登记时就写死，事后不可改。
    """

    did: str
    parent_did: str = ""
    agent_type: str = "primary"        # primary | sub
    state: DidState = DidState.ACTIVE
    cscid: str = ""                    # 监管公钥加密的 H(ID)（十进制字符串）
    ecid_ref: str = ""                 # 指向 IPFS 上那份信封的加密标识
    revoked_at: str = ""
    revoke_reason: str = ""
    # 级联来源：自己被吊销，还是因为父体被吊销
    revoke_source: str = ""
    registered_at: str = ""
    confirmed_by_user: bool = False    # 主智能体无此要求；子体必须为 True

    def to_json(self) -> dict:
        return {
            "did": self.did,
            "parentDid": self.parent_did,
            "agentType": self.agent_type,
            "state": self.state.value,
            # ★ cscid 不出现在任何对外响应里 —— 它是密文没错，
            #   但把它发出去等于把"打开身份的钥匙胚"到处复制。
            "ecidRef": self.ecid_ref,
            "revokedAt": self.revoked_at,
            "revokeReason": self.revoke_reason,
            "revokeSource": self.revoke_source,
            "registeredAt": self.registered_at,
            "confirmedByUser": self.confirmed_by_user,
        }

    @classmethod
    def from_json(cls, d: dict) -> "DidRecord":
        return cls(
            did=d.get("did", ""),
            parent_did=d.get("parentDid", ""),
            agent_type=d.get("agentType", "primary"),
            state=DidState(d.get("state", "active")),
            cscid=d.get("cscid", ""),
            ecid_ref=d.get("ecidRef", ""),
            revoked_at=d.get("revokedAt", ""),
            revoke_reason=d.get("revokeReason", ""),
            revoke_source=d.get("revokeSource", ""),
            registered_at=d.get("registeredAt", ""),
            confirmed_by_user=bool(d.get("confirmedByUser", False)),
        )

    # ---- 状态迁移 ----
    def revoke(self, *, reason: str, at: str, source: str = "direct") -> None:
        if self.state is DidState.REVOKED:
            return          # 幂等：级联会重复扫到同一个 DID
        self.state = DidState.REVOKED
        self.revoke_reason = reason
        self.revoked_at = at
        self.revoke_source = source


@dataclass
class Lineage:
    """一次上溯的结果：[子, ..., 主]。"""

    chain: list[str] = field(default_factory=list)

    @property
    def root(self) -> str:
        return self.chain[-1] if self.chain else ""

    @property
    def depth(self) -> int:
        return max(len(self.chain) - 1, 0)


__all__ = [
    "DidState", "DidRecord", "Lineage",
    "RegistryError", "DuplicateDid", "UnknownDid",
]
