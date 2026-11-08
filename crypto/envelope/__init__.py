"""加密信封层 —— SecInfo 打包与 CID 保护。

★ 红线 12：T1（找回）与 R2（追溯）共用这一套"还原"内核，
  禁止在两处各写一遍 —— 所以只有这一个实现。
★ 红线 17：CID 不得明文落盘，必须经 protect_cid() 变成 ECID。
"""

from . import cipher, kdf, sealinfo
from .kdf import derive_key
from .sealinfo import protect_cid, recover_cid, seal_secinfo, unseal_secinfo

__all__ = [
    "cipher", "kdf", "sealinfo",
    "derive_key",
    "seal_secinfo", "unseal_secinfo",
    "protect_cid", "recover_cid",
]
