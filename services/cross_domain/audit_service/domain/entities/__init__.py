"""audit-service 的领域实体：审计条目、链核验结论。"""

from .audit import (
    AuditEntry,
    ChainVerdict,
    canonical,
    digest_of,
    entry_hash,
    verify_entries,
)

__all__ = ["AuditEntry", "ChainVerdict", "canonical", "digest_of",
           "entry_hash", "verify_entries"]
