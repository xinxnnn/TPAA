"""查询与上溯。

`trace` 是追溯链上最关键的一步：拿到一个作恶的子体 DID，
必须能一路往上走回那个自然人名下的主 DID。走不到根，就等于只能封一个马甲。

上溯本身由 `crypto.sdk.trace_to_root` 完成 —— 哈希链与环检测都在密码层，
这里只负责把注册表翻译成它要的形态，并把结果说成人话。

一个刻意保留的行为：**查不到就是查不到**，不猜、不模糊匹配。
追溯的结论要能进取证包，任何"大概是这个"都会在法庭上被打回来。
"""

from __future__ import annotations

import crypto.sdk

from ..entities import DidRecord, Lineage, UnknownDid


class ResolveDidUseCase:
    """解析单个 DID。"""

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, did: str) -> DidRecord:
        rec = self.ctx.registry.get(did)
        if rec is None:
            raise UnknownDid(f"{did} 未登记")
        return rec


class TraceLineageUseCase:
    """沿 parent_did 上溯到根。"""

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, did: str) -> Lineage:
        rec = self.ctx.registry.get(did)
        if rec is None:
            raise UnknownDid(f"{did} 未登记，无法上溯")

        # 把注册表翻译成派生引擎要的形态：did -> DerivationRecord
        records = {}
        for d, r in self.ctx.registry.all().items():
            records[d] = crypto.sdk.DerivationRecord(
                child_did=d,
                parent_did=r.parent_did,
                agent_type=r.agent_type,
                confirmed_by_user=r.confirmed_by_user,
            )

        chain = crypto.sdk.trace_to_root(did, records)
        return Lineage(chain=list(chain))


class ChildrenOfUseCase:
    """查某个 DID 的直接子体 —— 级联吊销的入口。"""

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, did: str) -> list[str]:
        return sorted(d for d, r in self.ctx.registry.all().items()
                      if r.parent_did == did)


__all__ = ["ResolveDidUseCase", "TraceLineageUseCase", "ChildrenOfUseCase"]
