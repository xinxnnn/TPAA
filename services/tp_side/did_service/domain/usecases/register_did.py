"""登记 DID。

这是 TP 侧第一次拿到 H(ID) 的时刻，也是**唯一一次**允许明文经过的时刻。
所以顺序被写死：先封存、再落盘 —— 明文只活在这一个函数的作用域里。

三个不变量：

1. **DID 唯一**。重复登记直接拒绝：派生链靠 parent_did 上溯，
   一个号挂两个父亲，上溯就变成了猜。
2. **父体必须已登记**。子体不能凭空认父亲 —— 否则"上溯到根"永远到不了根，
   追溯会在半路断掉，而断掉的那一层恰好是最该被看见的那层。
3. **子体必须带用户确认**。没有确认证据的派生记录视为非法（§8 第 2 条），
   这条在登记时就卡住，而不是等追溯时才发现"这条链不合法"。
"""

from __future__ import annotations

from dataclasses import dataclass

import crypto.sdk

from ..entities import DidRecord, DidState, DuplicateDid, RegistryError


@dataclass(frozen=True)
class RegisterCommand:
    did: str
    identity_hash: int             # H(ID) 明文 —— 只在本用例内存在
    parent_did: str = ""
    ecid_ref: str = ""
    confirmed_by_user: bool = False
    confirm_evidence: dict | None = None


@dataclass(frozen=True)
class RegisterResult:
    did: str
    parent_did: str
    agent_type: str
    registered_at: str
    cscid_sealed: bool             # 只回"封好了"，不回密文


class RegisterDidUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RegisterCommand) -> RegisterResult:
        if not cmd.did.strip():
            raise RegistryError("DID 不能为空")

        existing = self.ctx.registry.get(cmd.did)
        if existing is not None:
            raise DuplicateDid(
                f"{cmd.did} 已登记 —— DID 必须唯一，重复会让上溯变成猜")

        parent_did = cmd.parent_did.strip()
        agent_type = "primary"
        if parent_did:
            parent = self.ctx.registry.get(parent_did)
            if parent is None:
                raise RegistryError(
                    f"父体 {parent_did} 未登记 —— 子体不能凭空认父亲，"
                    "否则追溯链会在这一层断掉")
            if parent.state is not DidState.ACTIVE:
                raise RegistryError(
                    f"父体 {parent_did} 已处于 {parent.state.value}，不能派生子体")
            agent_type = "sub"
            if not cmd.confirmed_by_user:
                raise RegistryError(
                    "子体登记必须携带用户确认证据 —— 未确认的派生视为非法")

        # ★ 先封存，再落盘：明文到此为止
        cscid = crypto.sdk.seal_identity(cmd.identity_hash, self.ctx.supervision_pub)

        now = self.ctx.clock.now()
        rec = DidRecord(
            did=cmd.did,
            parent_did=parent_did,
            agent_type=agent_type,
            cscid=str(cscid),
            ecid_ref=cmd.ecid_ref,
            registered_at=now,
            confirmed_by_user=cmd.confirmed_by_user,
        )
        self.ctx.registry.put(rec)
        return RegisterResult(
            did=rec.did, parent_did=rec.parent_did, agent_type=rec.agent_type,
            registered_at=now, cscid_sealed=bool(rec.cscid),
        )


__all__ = ["RegisterCommand", "RegisterResult", "RegisterDidUseCase"]
