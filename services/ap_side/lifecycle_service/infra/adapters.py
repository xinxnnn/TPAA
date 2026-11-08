"""lifecycle-service 的端口实现。

`AgentOpsAdapter` 直接使用 agent-service 的用例上下文 ——
两者在同一个 AP 域、同一台机器上，共享同一个 localstore。
这是"编排者调用原子能力"的关系，不是"跨服务复制逻辑"。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.ports import RecoverOutcome


@dataclass
class AgentOpsAdapter:
    """委托 agent-service 执行 RE。"""

    agent_ctx: object

    def _uc(self):
        from services.shared.modules import service_module

        return service_module("ap-side/agent-service", "domain.usecases")

    def recover(self, *, identity_hash: int, did: str) -> RecoverOutcome:
        uc = self._uc()
        out = uc.RecoverAgentUseCase(self.agent_ctx).execute(
            identity_hash=identity_hash, did=did)
        return RecoverOutcome(
            did=out.did, rebuilt=out.rebuilt, cmi=out.cmi,
            build_digest=out.build_digest,
            build_digest_changed=out.build_digest_changed, note=out.note)


__all__ = ["AgentOpsAdapter"]
