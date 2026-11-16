# 记忆状态与密钥库支撑

`crypto/memauth/memory.py` 实现 PDF p7 的已编码点级 MemBuild/CREATE、APPEND 的 P/CP 不变结论以及 p8 InitSync 的 G2 消失多项式见证。不提供完整事件 APPEND、图分类、凭证签发或认证；不自动选择哈希或修正原文符号。

状态不可变，含初始多项式、当前多项式、点、承诺、身份锚、SRS 标识。每次输入验证点约束、真实承诺、字段与次数，更新构造新对象；失败不提交。Nmax=dmax 同时限制宏节点数，实际多项式/G2 见证另查次数。theta 由调用方按原公式派生后传入，只在调用期间使用，不进入返回状态或默认展示。

CREATE 的具体公式执行：Phi=(X-theta)×历史点消失因子，插值 Q，再求 P_new=P+Q×Phi。验证新旧点和 P_new(theta)=P0(theta)。theta 碰撞导致分母为零时拒绝，不私自重采样或去重。该原语不是用户授权服务；原始 sUser/skPA 不出现在其接口。

`crypto/memauth/vault.py` 是已确认的本地软件支撑，格式与基线报文隔离。独立口令经 scrypt(N=32768,r=8,p=1) 派生 32 字节密钥，随机盐和 AES-256-GCM；头部作为 AAD。固定 KDF 参数避免读取恶意工件时被迫分配任意资源。只允许 skPA/rho0 两个秘密字段，不接受 sUser/theta/口令字段。PHC 与记忆持久化尚未接入，因此这不是完整 PA 持久化服务。

新建文件先写完临时兄弟文件，再通过硬链接独占发布；拒绝覆盖已有密钥库，无恢复/重置逻辑。文件夹应由部署方限制为当前用户可访问；Python 和本机文件权限不是硬件 TEE，也无法保证内存安全擦除。本实现尚未暴露 RPC 服务。

`packages/tpaa_runtime/memory_adapter.py` 为后续 AG2 预留事件、图邻接和可信网关接口，不依赖 AG2，不接收私钥、授权点或用户主秘密。接口存在不代表 AG2 已真实集成。

运行测试：

```powershell
python -m unittest discover -s tests/unit -p 'test_memauth_*.py' -v
python -m crypto.memauth.readiness
```

尚需确认的具体算法见 readiness 输出；已确认不勘误的认证项继续维持诊断状态，不反复请求同一授权。
