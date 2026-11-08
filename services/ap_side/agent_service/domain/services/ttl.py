"""TTL 清扫：过期子体转为冻结。

为什么是"冻结"而不是"删除"或"直接不可见"：
    子体过期往往意味着一段任务结束了，也可能是「有人在用长期有效的子体躲追溯」。
    两种情形都要留证据，所以只改状态、保留全部文件。
    真正的删除走 recycle/ 的软删窗口，那是另一条被人按下的路径。

幂等：已冻结/已吊销的实例直接跳过，重复清扫不会产生重复记录。
"""

from __future__ import annotations

from localstore import AgentState, AgentType


def sweep_expired(ctx) -> list[str]:
    """返回本次被冻结的 DID 列表（供审计与服务端日志）。"""
    now = ctx.clock.now()
    frozen: list[str] = []
    for meta in ctx.agents.iter_all():
        if meta.agent_type is not AgentType.SUB:
            continue                                  # 主智能体不过期
        if meta.state is not AgentState.ACTIVE:
            continue                                  # 幂等
        if not meta.expires_at or now <= meta.expires_at:
            continue

        # 父体已失效的子体一并冻结：这里不靠级联，而是按期判定，
        # 这样"父体异地被吊销、本机还没收到通知"时也能自愈。
        reason = "TTL 到期"
        if meta.parent_did:
            try:
                parent = ctx.agents.load_meta(meta.parent_did)
            except FileNotFoundError:
                parent = None
            if parent is not None and parent.state is not AgentState.ACTIVE:
                reason = f"TTL 到期且父体为 {parent.state.value}"
        ctx.agents.freeze(meta.did, reason, at=now)
        frozen.append(meta.did)
    return frozen


__all__ = ["sweep_expired"]
