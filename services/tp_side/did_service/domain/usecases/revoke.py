"""撤销一个 DID，并把它的全部后代一并撤销。

★ 为什么级联在这里、而不是在 policy-service 里：
    policy-service 决定"该不该吊销"（那是策略与授权的事），
    而"谁是它的后代"只有这张表知道。让策略层去遍历关系，
    等于让它持有一份关系的副本 —— 副本一旧，级联就漏人。
    所以：policy 下令，did-service 执行，谁掌握事实谁动手。

★ 主凭证吊销而子体继续跑 = 吊销形同虚设。
   这是本用例存在的唯一理由，所以它不提供"只吊销自己"的开关：
   想只吊销自己，就吊销一个没有后代的 DID。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import DidRecord, DidState, UnknownDid


@dataclass(frozen=True)
class RevokeCommand:
    did: str
    reason: str
    by: str = ""


@dataclass(frozen=True)
class RevokeResult:
    root: str
    revoked: list[str]              # 含根节点
    already_revoked: list[str]      # 幂等：扫到时已是撤销态


class RevokeDidUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RevokeCommand) -> RevokeResult:
        if not cmd.reason.strip():
            raise ValueError("吊销必须写明理由 —— 这条记录要进取证包")

        root = self.ctx.registry.get(cmd.did)
        if root is None:
            raise UnknownDid(f"{cmd.did} 未登记，无从吊销")

        now = self.ctx.clock.now()
        revoked: list[str] = []
        already: list[str] = []

        # 广度优先展开后代：先近后远，便于日志里看出"波及到第几层"
        frontier = [cmd.did]
        seen: set[str] = set()
        while frontier:
            cur = frontier.pop()
            if cur in seen:
                continue
            seen.add(cur)
            rec = self.ctx.registry.get(cur)
            if rec is None:
                continue

            source = "direct" if cur == cmd.did else "cascade"
            if rec.state is DidState.REVOKED:
                already.append(cur)
            else:
                rec.revoke(reason=cmd.reason, at=now, source=source)
                self.ctx.registry.put(rec)
                revoked.append(cur)

            for child in sorted(d for d, r in self.ctx.registry.all().items()
                                if r.parent_did == cur):
                frontier.append(child)

        return RevokeResult(root=cmd.did, revoked=revoked, already_revoked=already)


__all__ = ["RevokeCommand", "RevokeResult", "RevokeDidUseCase"]
