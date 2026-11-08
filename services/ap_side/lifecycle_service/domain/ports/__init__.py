"""lifecycle-service 的端口。

    StorePort        AP 自己的资产目录（localstore）—— 停运就在这一层发生
    AgentOpsPort     委托 agent-service 做"重建制品"这种原子能力
    Clock            时间

★ 为什么"停运"不委托给 agent-service：
  停运是**资产状态变更**，不是"某个服务的业务动作"。
  它必须在最靠近资产的那一层完成 —— 也就是这里。
  委托出去，中间就多了一段"通知还没到"的窗口，
  而那个窗口里的实例仍然能对外服务。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class AgentSnapshot:
    did: str
    state: str = ""
    agent_type: str = "primary"
    parent_did: str = ""
    expires_at: str = ""


@runtime_checkable
class StorePort(Protocol):
    def iter_all(self) -> list: ...

    def load_meta(self, did: str): ...

    def freeze(self, did: str, reason: str, *, at: str) -> None: ...

    def exists(self, did: str) -> bool: ...


@dataclass(frozen=True)
class RecoverOutcome:
    did: str
    rebuilt: bool = False
    cmi: str = ""
    build_digest: str = ""
    build_digest_changed: bool = False
    note: str = ""


@runtime_checkable
class AgentOpsPort(Protocol):
    def recover(self, *, identity_hash: int, did: str) -> RecoverOutcome:
        """委托 agent-service 执行 RE（重算 CMI → 重建 build）。

        ★ 为什么这件事要委托：
          "重建制品"要用到模块仓库解析、确定性组装、算法1 的自证 ——
          这些能力都在 agent-service 里，复制一份到 lifecycle 就是第二份真相。
          lifecycle 的职责是**编排**：决定该不该做、什么时候做、失败怎么办。
        """
        ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str: ...


__all__ = ["AgentSnapshot", "StorePort", "AgentOpsPort", "RecoverOutcome", "Clock"]
