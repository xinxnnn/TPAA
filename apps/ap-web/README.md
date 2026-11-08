# TPAA 智能体提供方控制台（ap 区）

能力模块库、主智能体实例与 CMI、子智能体派生记录、升级/找回任务。

- 允许访问：`/api/ap` → agent-service, subagent-service, lifecycle-service
- 禁止：直连其他区的前端 URL；前端做加解密或持有密钥
- 边界由 `scripts/check_frontend_boundary.py` 在 CI 静态强制
