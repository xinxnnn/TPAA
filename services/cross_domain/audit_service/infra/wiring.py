"""audit-service 的装配。"""

from __future__ import annotations

from ..domain.services.context import AuditContext, ConfigError
from .attest import PhcAttachments
from .clock import SystemClock
from .ledger import AuditLedger


def build_context(*, db_path: str, attest_path: str | None = None,
                  clock=None) -> AuditContext:
    ctx = AuditContext(
        ledger=AuditLedger(db_path),
        attest=PhcAttachments(attest_path) if attest_path else None,
        clock=clock or SystemClock(),
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, db_path: str, clock=None) -> AuditContext:
    """演练装配：账本与存证都落到同一目录。"""
    from pathlib import Path

    base = Path(db_path)
    return build_context(db_path=str(base), clock=clock,
                         attest_path=str(base.with_name(base.stem + "-attest.json")))


__all__ = ["build_context", "build_dev_context", "ConfigError"]
