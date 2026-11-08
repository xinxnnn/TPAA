"""HSM 适配层。

生产替换点：把 `SoftHSM` 换成真实 HSM / KMS 的适配实现即可，上层接口不变。
"""

from __future__ import annotations

from .base import HSM
from .soft import SoftHSM
from .supervision import SupervisionKey, SupervisionPublic

__all__ = ["HSM", "SoftHSM", "SupervisionKey", "SupervisionPublic"]
