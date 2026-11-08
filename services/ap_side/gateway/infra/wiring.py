"""gateway 的装配。

★ 三种装配，对应三种部署形态：

    build_context           显式注入全部端口（生产）
    build_dev_context       全部走进程内（单体 / 本地演练）
    build_http_context      通道走 HTTP，其余进程内（分区部署的第一步）

  第三种存在的意义：它是"换适配器即可分区部署"这句话的**可执行形态**。
  不是文档里的一句承诺，而是一行能跑起来的装配。
"""

from __future__ import annotations

from ..domain.services.context import ConfigError, GatewayContext
from .adapters import LocalAssist, LocalAudit, LocalChannel, LocalStop
from .clock import SystemClock


def build_context(*, channel, assist, audit, clock=None, stop=None,
                  self_id: str = "AP", allowed_kinds=("lineage_proof",),
                  batch_limit: int = 50) -> GatewayContext:
    ctx = GatewayContext(
        channel=channel, assist=assist, audit=audit,
        clock=clock or SystemClock(), stop=stop, self_id=self_id,
        allowed_kinds=tuple(allowed_kinds), batch_limit=batch_limit,
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, coord_ctx, lifecycle_ctx, audit_ctx, clock=None,
                      self_id: str = "AP",
                      allowed_kinds=("lineage_proof",)) -> GatewayContext:
    """全部进程内。⚠️ 只用于测试与演示 —— 它没有真正跨进程。"""
    return build_context(
        channel=LocalChannel(coord_ctx=coord_ctx),
        assist=LocalAssist(lifecycle_ctx=lifecycle_ctx),
        stop=LocalStop(lifecycle_ctx=lifecycle_ctx),
        audit=LocalAudit(audit_ctx=audit_ctx),
        clock=clock, self_id=self_id, allowed_kinds=allowed_kinds)


def build_http_context(*, base_url: str, lifecycle_ctx, audit_ctx, clock=None,
                       self_id: str = "AP", allowed_kinds=("lineage_proof",),
                       timeout: float = 5.0, client=None) -> GatewayContext:
    """通道走 HTTP，其余进程内 —— 分区部署。

    client 可注入：测试里传 TestClient（打一个真起起来的 coordination），
    生产里留空（适配器自己管一个 httpx.Client，用完即关）。
    """
    from .adapters import HttpChannel

    return build_context(
        channel=HttpChannel(base_url=base_url, timeout=timeout, client=client),
        assist=LocalAssist(lifecycle_ctx=lifecycle_ctx),
        stop=LocalStop(lifecycle_ctx=lifecycle_ctx),
        audit=LocalAudit(audit_ctx=audit_ctx),
        clock=clock, self_id=self_id, allowed_kinds=allowed_kinds)


__all__ = ["build_context", "build_dev_context", "build_http_context",
           "ConfigError"]
