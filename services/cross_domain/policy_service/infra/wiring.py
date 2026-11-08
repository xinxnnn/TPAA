"""policy-service 的装配。"""

from __future__ import annotations

from ..domain.services.context import ConfigError, PolicyContext
from .adapters import LocalAudit, LocalDirectory, LocalNotify
from .clock import SystemClock
from .orders import OrderStore


def build_context(*, db_path: str, directory, notify, audit,
                  clock=None) -> PolicyContext:
    ctx = PolicyContext(orders=OrderStore(db_path), directory=directory,
                        notify=notify, audit=audit,
                        clock=clock or SystemClock())
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, db_path: str, did_ctx, lifecycle_ctx, audit_ctx,
                      clock=None) -> PolicyContext:
    return build_context(
        db_path=db_path,
        directory=LocalDirectory(did_ctx=did_ctx),
        notify=LocalNotify(lifecycle_ctx=lifecycle_ctx),
        audit=LocalAudit(audit_ctx=audit_ctx),
        clock=clock,
    )


__all__ = ["build_context", "build_dev_context", "ConfigError"]
