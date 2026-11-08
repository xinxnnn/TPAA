"""找回（RE）的编排。

★ lifecycle 只做编排，不重写算法。
  "重算 CMI → 比对 → 确定性重建" 那一套在 agent-service 里已经实现并测过；
  在这里复制一份，等于给同一个承诺留两个实现 ——
  两份一旦对不上，用户会拿到一个"看起来找回成功、其实内容不同"的智能体。

所以本用例做的是**前置判断**：

    0  实例必须存在且在本机
    1  状态必须 active（冻结/吊销的不重建 —— 那正是追溯要保住的状态）
    2  子体：父体也必须 active
    3  子体：自己不能已过期
    然后才委托重建

这四条判断的顺序也是刻意的：**先判断该不该做，再决定怎么做**。
反过来的话，一个不该被重建的实例已经被重建完了，才发现不该。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import LifecycleError


@dataclass(frozen=True)
class RecoverCommand:
    did: str
    identity_hash: int


@dataclass(frozen=True)
class RecoverResult:
    did: str
    rebuilt: bool
    cmi: str
    build_digest: str
    build_digest_changed: bool
    note: str


class RecoverUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RecoverCommand) -> RecoverResult:
        if not self.ctx.store.exists(cmd.did):
            raise LifecycleError(f"{cmd.did} 不在本机 —— 请确认 AP 节点")

        meta = self.ctx.store.load_meta(cmd.did)

        # 1) 状态
        if meta.state.value == "frozen":
            raise LifecycleError(
                f"{cmd.did} 已冻结（{meta.frozen_reason or '未记录'}）—— "
                "冻结实例不重建：那正是需要保住的现场。请先由运维复核。")
        if meta.state.value == "revoked":
            raise LifecycleError(f"{cmd.did} 已吊销，不重建")

        # 2) 父体
        if meta.parent_did:
            if not self.ctx.store.exists(meta.parent_did):
                raise LifecycleError(
                    f"{cmd.did} 的父体 {meta.parent_did} 不在本机 —— 先找回父体")
            parent = self.ctx.store.load_meta(meta.parent_did)
            if parent.state.value != "active":
                raise LifecycleError(
                    f"父体 {meta.parent_did} 为 {parent.state.value}，"
                    "不能单独找回子体")

            # 3) 过期
            now = self.ctx.clock.now()
            if meta.expires_at and now > meta.expires_at:
                raise LifecycleError(
                    f"{cmd.did} 已于 {meta.expires_at} 过期 —— "
                    "过期子体不找回，请重新派生（追溯需要它保持过期状态）")

        out = self.ctx.agent_ops.recover(identity_hash=cmd.identity_hash,
                                         did=cmd.did)
        return RecoverResult(did=out.did, rebuilt=out.rebuilt, cmi=out.cmi,
                             build_digest=out.build_digest,
                             build_digest_changed=out.build_digest_changed,
                             note=out.note)


__all__ = ["RecoverUseCase", "RecoverCommand", "RecoverResult"]
