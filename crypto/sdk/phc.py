"""PHC 引擎的受限对外入口（经 crypto.sdk，不接受越权直连）。"""

from __future__ import annotations

from ..phc.engine import issue_phc, update_by_ap, update_by_tp
from ..phc.engine import verify_phc as _verify_engine

__all__ = ["issue_phc", "update_by_ap", "update_by_tp", "verify_phc"]


def verify_phc(phc, **kw):
    """校验 PHC。**同时接受 PHC 对象与 JSON-LD dict**。

    ★ 为什么不在 `__init__` 里直接重导出引擎那个 `verify_phc`：
      引擎只接受 PHC 对象，而业务侧手里拿的一律是 JSON（跨域交换的唯一形态）。
      上游若照直觉传 dict 进去，会在 `phc.apch_message()` 处以
      `'dict' object has no attribute 'apch_message'` 崩掉 ——
      那看起来像"验签逻辑坏了"，实际只是入参没转。这种错查起来代价很高，
      所以在 sdk 这一层把两种形态都接住：**sdk 是给业务用的，就该接业务手里的形态**。
    """
    if isinstance(phc, dict):
        from .phc_io import phc_json_to_obj
        phc = phc_json_to_obj(phc)
    return _verify_engine(phc, **kw)
