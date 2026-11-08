"""本服务调用密码学能力的唯一入口（红线 2 / ARCHITECTURE §7.2）。

❌ 禁止：直连 crypto 内部实现（primitives / phc / derivation / envelope）
✅ 允许：只经 crypto.sdk（或 crypto.hsm）。CI 的 crypto.guard 会静态拦截越权。

★ 必须写 `import crypto.sdk` 再用属性访问，**不能** `from crypto.sdk import x`：
  from-import 会把具体函数捕进本模块命名空间，调用处再也看不出"这是密码边界"，
  guard R2 也会把它判定为越界（`crypto.sdk` 与 `crypto.sdk/*` 均不让 from-import）。
"""

import crypto.sdk

__all__ = ["crypto"]
