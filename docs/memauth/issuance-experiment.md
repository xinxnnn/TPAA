# Phase 0 本机角色仿真

`issuance_experiment.py` 仅在已批准的可执行实验配置下实例化 PHCInit、PAConstruct、PHCFinalize。基线没有新增报文、哈希默认或公式勘误。真实身份核验、可信交付和访问控制尚未实现，不能称为可部署签发服务。

IRF 使用 Paillier g=n+1，随机数从 Zn* 采样；AP 计算 sAP 并通过加密乘法产生 RF。验证输入密文范围及单位群条件。PA 独立产生非零 skPA，TP 只取得公钥。TP 采样 rho0，计算 hRoot0、y0、deltaTP、全局 KTP 和 RegPA；不计算记忆多项式。

DID 后缀的域元素使用十进制字符串是本地序列化，不是新的密码规则。CMC 作为有序 tuple 输入，编码采用已批准配置；演示使用明确的合成能力标识。论文未具体定义身份 H，本实验以批准的 H1 映射合成身份字符串，不使用或持久化真实 PII。

全局 KTP 完全保留 PRF_c1(DIDTP||c2)，未加入 DIDPA。不同 PA 使用相同 TP 参数得到同一 KTP 的测试已覆盖；原文风险见代数审查。

运行 `demos.memauth.registration_memory`：实际生成 2048 位 Paillier 模数，执行角色公式、固定基底签名、审计事件、初始记忆、APPEND/CREATE 和 G2 见证。与较早的 audit_memory 夹具演示不同，该入口 RF/y0 来自本次计算，不用合成密文常量替代。所有身份和事件仍为合成数据。

记录默认不输出 skPA、TP/AP 私钥、KTP、sUser、theta、rho、身份哈希、y0、多项式系数。RF、签名和 PA 公钥仅为已批准的注册审计白名单；记录可关联注册，不当作匿名认证转录。进程内角色能访问本地变量，这是本机编排器，不是独立进程可信模块。

Bootstrap/连续认证未执行。用户已决定不修正文中未定义符号/新旧承诺冲突，因此工作台只展示诊断状态，不生成看似通过的完整认证证明。
