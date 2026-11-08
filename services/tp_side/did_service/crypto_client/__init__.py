"""did-service 调用密码学能力的唯一入口（红线 2）。

❌ 禁止：直连 crypto 内部实现
✅ 允许：只经 crypto.sdk，且用包级 import + 属性访问（`from crypto.sdk import x` 会被 guard R2 拦下）
"""

import crypto.sdk

__all__ = ["crypto"]
