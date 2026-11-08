"""领域实体：本服务自己的概念，不依赖 FastAPI、不依赖 localstore、不依赖 crypto。

一个原则：**实体只描述"是什么"和"允许怎么变"**，不描述"存哪里"。
状态迁移写成显式方法并拒绝非法迁移 —— 这样「已冻结的实例不能被当作正常实例交付」
是模型层面的结论，而不是某条 API 里的一个 if。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class State(str, Enum):
    ACTIVE = "active"
    FROZEN = "frozen"
    REVOKED = "revoked"


class IllegalTransition(RuntimeError):
    """非法状态迁移 —— 冻结后不得交付、吊销后不得找回，都属此类。"""


@dataclass
class Agent:
    """一个智能体实例（主或子）。"""

    did: str
    owner_did: str
    identity_hash: str
    agent_type: str = "primary"          # primary | sub
    parent_did: str = ""
    expires_at: str = ""
    state: State = State.ACTIVE
    frozen_reason: str = ""

    # ---- 状态迁移 ----
    def ensure_deliverable(self) -> None:
        """交付前的最后一道：状态必须是 ACTIVE。

        冻结实例仍留在磁盘上是为了取证，但**绝不能**被当成正常实例交付出去。
        """
        if self.state is State.FROZEN:
            raise IllegalTransition(
                f"实例已冻结，不能交付（原因：{self.frozen_reason or '未记录'}）；"
                "请先由运维复核后再解冻")
        if self.state is State.REVOKED:
            raise IllegalTransition("实例已吊销，不能交付")

    def freeze(self, reason: str) -> None:
        if self.state is State.REVOKED:
            raise IllegalTransition("已吊销的实例不能再冻结")
        self.state = State.FROZEN
        self.frozen_reason = reason

    def thaw(self, *, reviewed_by: str) -> None:
        """解冻是**人工**动作，且必须留下复核人。"""
        if self.state is not State.FROZEN:
            raise IllegalTransition("只有冻结中的实例可以解冻")
        if not reviewed_by:
            raise IllegalTransition("解冻必须记录复核人")
        self.state = State.ACTIVE
        self.frozen_reason = ""


@dataclass(frozen=True)
class ModuleChoice:
    module_id: str
    version: str


@dataclass(frozen=True)
class Selection:
    """用户的选择向量。**顺序由平台归一化，不由前端决定**。"""

    choices: tuple[ModuleChoice, ...] = ()

    def normalized(self) -> tuple[ModuleChoice, ...]:
        return tuple(sorted(self.choices, key=lambda c: (c.module_id, c.version)))

    def contains(self, module_id: str, version: str) -> bool:
        return any(c.module_id == module_id and c.version == version for c in self.choices)


@dataclass(frozen=True)
class ConfirmToken:
    """派生闸门的确认凭据：一次一用、绑定到具体方案。

    为什么要绑方案摘要：光有「用户点过确认」四个字是不够的 ——
    确认之后把模块从 A 换成 B，再用同一张令牌去过闸门，等于确认被偷换了内容。
    """

    token: str
    selection_digest: str
    confirmed_at: str
    consumed_at: str = ""

    @property
    def used(self) -> bool:
        return bool(self.consumed_at)


@dataclass
class ChildRequest:
    """派生子体的意图。**必须携带确认令牌**，没有令牌就不进入任何密钥动作。"""

    parent_did: str
    selection: Selection
    ttl_hours: int
    confirmation: ConfirmToken | None

    def guard(self) -> None:
        if self.confirmation is None:
            raise NotConfirmed("派生子智能体必须先由用户手动确认（缺少确认令牌）")
        if self.confirmation.used:
            raise NotConfirmed("确认令牌已被使用过，请重新发起并确认")
        if self.confirmation.selection_digest != digest_selection(self.selection):
            raise NotConfirmed(
                "确认令牌与本次选择不一致 —— 确认后方案被改动，请重新确认")


class NotConfirmed(PermissionError):
    """派生闸门未通过。用 PermissionError 的子类，语义上就是「不许做」。"""


def digest_selection(sel: Selection) -> str:
    """选择向量的稳定摘要。同一意图必须得到同一摘要，否则确认无法绑定。"""
    import hashlib

    h = hashlib.sha256()
    for c in sel.normalized():
        h.update(f"{c.module_id}@{c.version}\n".encode())
    return h.hexdigest()


__all__ = [
    "Agent", "State", "IllegalTransition", "Selection", "ModuleChoice",
    "ConfirmToken", "ChildRequest", "NotConfirmed", "digest_selection",
]
