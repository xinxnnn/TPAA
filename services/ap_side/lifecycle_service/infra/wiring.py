"""lifecycle-service 的装配。

★ 它接的是 agent-service 的**同一个** localstore 与同一个上下文 ——
  两台服务必须看到同一批文件，否则"停运"会停在一份没人在用的副本上。
  这在生产上意味着两者必须挂同一个卷；做不到时，就该把 lifecycle 合并进
  agent-service，而不是让两份存储各自演化。
"""

from __future__ import annotations

from pathlib import Path

from localstore import AgentStore, Layout

from ..domain.services.context import ConfigError, LifecycleContext
from .adapters import AgentOpsAdapter
from .clock import SystemClock


def build_context(*, store_root: str, agent_ctx, clock=None) -> LifecycleContext:
    if agent_ctx is None:
        raise ConfigError(
            "缺少 agent-service 上下文 —— lifecycle 的找回要委托给它，"
            "没有它就只能停运、不能找回")

    ctx = LifecycleContext(
        store=AgentStore(Layout(Path(store_root))),
        agent_ops=AgentOpsAdapter(agent_ctx=agent_ctx),
        clock=clock or SystemClock(),
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, store_root: str, agent_ctx, clock=None) -> LifecycleContext:
    return build_context(store_root=store_root, agent_ctx=agent_ctx, clock=clock)


__all__ = ["build_context", "build_dev_context", "ConfigError"]
