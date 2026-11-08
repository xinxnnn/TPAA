# TPAA 可信第三方控制台（tp 区）

人工核验审批、凭证台账与吊销、DID 与父子关系、举报→立案→协查→取证。

- 允许访问：`/api/tp` → identity-service, review-service, phc-service, did-service, supervision-service
- 禁止：直连其他区的前端 URL；前端做加解密或持有密钥
- 边界由 `scripts/check_frontend_boundary.py` 在 CI 静态强制
