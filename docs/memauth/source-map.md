# MemAuth P0 原文映射

状态：原文映射与代数审查，2026-11-10。页码为 PDF 印刷页码。

| 位置 | 算法或关系 | 计划实现 | 计划验证 | 状态 |
|---|---|---|---|---|
| p4 §III A–C | 配对群、PS、KZG | pairing_backend、ps、kzg | 独立向量及非法群点 | py-ecc 8.0.0/BLS12-381；KZG、PS 及重随机化已实现 |
| p4 §III D–E | Merkle、CH.Gen/Adapt | merkle、chameleon、encoding | 序列篡改与适配等式 | 抽象 H/编码显式传入；未定义奇数层规则默认停止；已确认实验配置独立 |
| p6 Phase 0 Setup | 双群 SRS、Paillier、c1/c2 | srs、credentials | 次数与参数一致性 | 双群 SRS 及离线实验生成已实现；其余待实现 |
| p6 PHCInit | IRF | issuance_experiment | Paillier 明文关系 | 显式实验已实现；身份核验为仿真 |
| p6 PAConstruct | sAP、RF | issuance_experiment | 同态关系、模空间 | 实验实现；与 TPAA PRF 用途隔离 |
| p6 PHCFinalize | PA 生成密钥、y0、sigmaTP、KTP、RegPA | issuance_experiment、ps | 签名和身份锚关系 | 本机角色实验已接通；安全交付服务未实现；保留全局 KTP |
| p7 式1–3 | 事件、宏节点、插值 | memory、polynomial | 编码、求值、承诺 | polynomial.py 已实现精确域运算与插值；H/序列编码未完全规定 |
| p7 MemBuild | 初始三点与承诺 | memory、audit_events | P0(0)=y0 | 点级实现、显式事件配置和独立审计适配已完成；完整签发未接入 |
| p7 Adjudicate | 邻接频次与确定性平局 | graph adapter | CREATE/APPEND | 已确认合成图规则独立实现；抽象基线不默认补齐 |
| p7 MemUpdate | APPEND、CREATE、授权点 | memory | 旧点、新点、授权点及次数 | CREATE 点级转移已实现；APPEND 仅不变结论；事件/CH 接线未实现 |
| p7–8 InitProve/Verify | PS 盲化与 link | bootstrap | 原文等式逐项执行 | h^alpha 已视觉核验；Pz/gamma_C 命名待确认 |
| p8 InitSync | 消失多项式与 G2 见证 | memory、bootstrap | W 与同步点集合 | G2 见证已实现；完整角色同步未实现 |
| p8 ContChallenge | SA 密钥及身份查找 | continuity | 请求签名 | PKPA 对 SA 的可用性待澄清 |
| p8 ContProve/Verify | topo、open、upd、link | continuity_primitives | 三证明及微观序列 | open/upd 原语真实配对已实现；完整验证因 link/运输疑点保持诊断 |
| p8 Phase 4 | 解盲、AP 协作、身份恢复 | accountability_experiment | 注册一致性 | 分角色等式已实现并接入实验；真实审批/通道未实现；全局 KTP 风险单列 |
| p9 §VI | 安全游戏与证明 | 审查文档与反例实验 | 假设对照 | 不以运行成功替代安全证明 |

PDF 明确提到 compaction，但未给出足够的完整算法与验证步骤；按用户决议不在基线实现。不能将其描述为已完整定义的算法，也不应称原文完全未提及。

原文提取同时使用 layout/raw 模式交叉核对。已渲染并视觉核验第 4、6、7、8 页关键公式，确认 InitVerify 使用 h^alpha，Setup alpha 采样 Fq*；文本提取遗漏上标的初始疑点及采样域误读已纠正。未核验的疑点不直接当作作者错误。

## P1 首批实现

真实配对、双群 SRS、KZG 和公开计算 trace 的运行方法及限制见 `p1-crypto-primitives.md`。这不改变原文诊断与暂不勘误的决议。

`crypto/memauth/polynomial.py`：不可变规范系数、有限域求值、加减乘、带余除法、精确除法、消失多项式、Lagrange 插值和实际次数检查。支持已知 BLS12-381 标量域及确定性素性检查通过的 64 位实验素数；这不表示已选定或实现配对后端。

`tests/unit/test_memauth_polynomial.py`：独立二次多项式向量、CREATE 代数约束、次数超限、重复域坐标、错误模数、非整除、零除数与跨域拒绝。运行 `python -m unittest discover -s tests/unit -p test_memauth_polynomial.py -v`。CREATE 测试仅验证明确的多项式关系，不实现身份认证、授权流程或未确认勘误。
