"""派生引擎：主智能体 → 子智能体。

    lineage.DerivationRecord   一次派生的存证（必须进审计链）
    lineage.derive_child_phc    生成带父指针的子体 PHC 骨架
    lineage.seal_child_did      TP 写入唯一 DID 并封印
    lineage.verify_lineage      校验父指针是否被密码学封住
    lineage.trace_to_root       上溯到主 DID（归属证明）
    lineage.cascade_revoke      主吊销 → 全部后代失效
"""

from . import lineage
from .lineage import (
    DerivationRecord,
    cascade_revoke,
    derive_child_phc,
    seal_child_did,
    trace_to_root,
    verify_lineage,
)

__all__ = [
    "lineage",
    "DerivationRecord",
    "derive_child_phc",
    "seal_child_did",
    "verify_lineage",
    "trace_to_root",
    "cascade_revoke",
]
