# TPAA 平台运营台（ops 区）

不属于 User/TP/AP 任何一方，只能访问跨域治理接口的只读视图。

- 允许访问：`/api/ops` → gateway, policy-service, audit-service, coordination
- 禁止：直连其他区的前端 URL；前端做加解密或持有密钥
- 边界由 `scripts/check_frontend_boundary.py` 在 CI 静态强制
