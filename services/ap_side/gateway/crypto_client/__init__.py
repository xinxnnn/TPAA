"""本服务调用密码学能力的唯一入口（红线 2 / ARCHITECTURE §7.2）。

❌ 禁止：直连 crypto 内部实现（primitives / phc / derivation / envelope）
✅ 允许：只经 crypto.sdk（或 crypto.hsm）。CI 的 crypto.guard 会静态拦截越权。

★ 必须写 `import crypto.sdk` 再用属性访问，**不能** `from crypto.sdk import x`：
  from-import 会把具体函数捕进本模块命名空间，调用处再也看不出"这是密码边界"，
  guard R2 也会把它判定为越界（`crypto.sdk` 与 `crypto.sdk/*` 均不让 from-import）。

★ gateway 实际上**不做任何密码学运算** —— 它只搬运 lifecycle 算好的公开材料。
  这份文件在在这里是为了说明"这里也不许破例"，而不是因为它需要。
"""

import crypto.sdk

__all__ = ["crypto"]
