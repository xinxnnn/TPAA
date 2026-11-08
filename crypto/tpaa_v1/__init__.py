"""tpaa_v1 —— 按《TPAA说明书》+ docs/protocol-errata 实现的协议 profile。

与 proto0（crypto/phc）并存、互不混用：PHC 带 `profile` 字段，校验前先认 profile。
上层只经 `crypto.sdk.v1` 调用（guard R2 管）。
"""

from .params import PARAMS_ID
from .schema import PROFILE

__all__ = ["PROFILE", "PARAMS_ID"]
