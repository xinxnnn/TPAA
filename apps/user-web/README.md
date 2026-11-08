# TPAA 用户端（user 区）

申领 PHC、申领主智能体、派生子智能体（需手动确认）、保险箱、找回/注销。

- 允许访问：`/api/user` → portal-api
- 禁止：直连其他区的前端 URL；前端做加解密或持有密钥
- 边界由 `scripts/check_frontend_boundary.py` 在 CI 静态强制
