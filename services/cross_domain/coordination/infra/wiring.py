"""coordination 的装配。"""

from __future__ import annotations

import os

from ..domain.services.context import ConfigError, CoordinationContext
from ..domain.services.rate_limit import Quota, RateLimiter
from .audit import MemoryAudit, NotImplementedAudit
from .clock import SystemClock
from .tickets import TicketStore


def build_context(*, db_path: str, audit, clock=None,
                  quota: Quota | None = None) -> CoordinationContext:
    ctx = CoordinationContext(
        tickets=TicketStore(db_path),
        audit=audit if audit is not None else NotImplementedAudit(),
        clock=clock or SystemClock(),
        limiter=RateLimiter(quota=quota),
        policy={"db": db_path},
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, db_path: str, clock=None) -> CoordinationContext:
    """演练装配：审计进内存。⚠️ 重启即丢，只用于测试与演示。"""
    return build_context(db_path=db_path, audit=MemoryAudit(), clock=clock)


def quota_from_env() -> Quota:
    return Quota(
        max_open=int(os.environ.get("TPAA_COORD_MAX_OPEN") or 20),
        max_per_hour=int(os.environ.get("TPAA_COORD_MAX_PER_HOUR") or 60),
    )


__all__ = ["build_context", "build_dev_context", "quota_from_env", "ConfigError"]
