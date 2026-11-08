"""SecInfo 信封 / CID 保护的受限对外入口（经 crypto.sdk，不接受越权直连）。"""

from __future__ import annotations

from ..envelope.sealinfo import seal_secinfo, unseal_secinfo, protect_cid, recover_cid

__all__ = ["seal_secinfo", "unseal_secinfo", "protect_cid", "recover_cid"]
