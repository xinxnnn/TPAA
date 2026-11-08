"""派生引擎的受限对外入口（经 crypto.sdk，不接受越权直连）。"""

from __future__ import annotations

from ..derivation.lineage import (
    derive_child_phc,
    seal_child_did,
    verify_lineage,
    trace_to_root,
    cascade_revoke,
    DerivationRecord,
)

__all__ = [
    "derive_child_phc", "seal_child_did", "verify_lineage",
    "trace_to_root", "cascade_revoke", "DerivationRecord",
]
