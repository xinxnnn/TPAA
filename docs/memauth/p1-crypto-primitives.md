# P1 密码原语首批交付

范围：PDF §III.C 的未盲化 KZG，及 Phase 0 的双群 SRS。不是完整 MemAuth 认证；不解释或修复 InitProve/ContVerify 的未决符号。

## 后端与安装

可选依赖 `py-ecc==8.0.0`、`pycryptodome==3.23.0`，分别提供真实 BLS12-381 群/配对和 Keccak-256；默认 TPAA 安装仍无此依赖。采用 Python 参考实现用于学术正确性实验，不宣称常数时间执行、生产性能或硬件防提取。实测依赖快照见 `requirements-memauth-experiment.txt`（Python 3.11/Windows）；这是环境快照，不是带哈希的跨平台供应链锁文件。

```powershell
python -m pip install -r docs/memauth/requirements-memauth-experiment.txt
python -m unittest discover -s tests/unit -p 'test_memauth_*.py' -v
```

`pairing_backend.py` 的边界是规范压缩字节（G1 48 字节、G2 96 字节）；解码检查曲线、子群和重新编码一致性。非法输入报错；合法编码但错误的 KZG 声明返回 false。零多项式和常数多项式允许单位元证明，不能无条件拒绝单位元。

## 独立实验

```powershell
python -m crypto.memauth.setup_experiment --degree 3 --output experiment-srs.json
python -m demos.memauth.kzg_public_trace --srs experiment-srs.json
```

Setup 独立进程生成公开 SRS，不返回、不序列化 alpha，不提供运行期恢复接口。输出文件以独占创建方式写入，拒绝覆盖。Python 无法保证进程内存中的 alpha 被安全擦除；进程退出不等于硬件安全擦除，也不是多方可信设置仪式。

原页第 6 页视觉复核确认 alpha 的采样域为 Fq*；已纠正此前将其误读为 Fq 的实现和记录，按原文非零采样并拒绝单位元 SRS 幂。这不改变原协议。一致性检查仍不能证明陷门已销毁、未知或独立随机。

SRS 检查双群序列长度、基生成元、所有点合法性和逐阶配对一致性；ID 是本地工件摘要，不增加基线报文字段。承诺和证明分别检查实际多项式次数，G2 多项式承诺也检查次数。逐阶检查在大 SRS 上较慢，当前没有以未评审的批量抽检替代。

公开 trace 仅使用固定合成多项式 P=13+5X+2X²、z=3，输出 y=46、商 Q=11+2X，以及真实承诺、证明、配对输入、合法/篡改校验和耗时。不读取真实 PA 的系数或秘密，不输出 alpha；尚未连接前端。

## 当前验证与边界

独立已知指数向量、双群关系、篡改拒绝、零/常数多项式、非法编码、非子群曲线点、超限、跨域、损坏 SRS 和工件元数据检查均有测试。已用单独随机设置进程运行公开 trace。

未完成：记忆状态协议、完整凭证签发、可信模块服务和前端研究工作台；未确认勘误仍不实现。不能以此模块测试通过声称论文全部安全结论成立。

## 后续原语：编码、Merkle、CH

`encoding.py` 的类型标记和长度前缀是本地编码工具；SHA-256 rejection-sampling hash-to-field 不默认绑定为原文 H0/H1。协议接线前仍需冻结论文级哈希映射和字段序列化。当前实现限定模数小于 2^256，拒绝不支持的宽度，防止错误采样。

`merkle.py` 仅固定论文 §III.D 的抽象公式 `H(0 || L)` 与 `H(1 || left || right)`；论文没有指定 Keccak。构建和验证必须显式传入 H、叶编码和摘要长度；遇未指定的奇数层规则抛出 UndefinedPaperRule，不默认补齐。空序列也拒绝。包含性证明仅供实验审计，计数是待验证的结构参数，不是额外认证的可信元数据；基线连续认证仍传递完整序列。

2026-11-10 用户确认：保留 Keccak-256＋现有类型编码＋复制末节点为显式实验配置。调用方必须主动选择 `experiment_profiles.keccak_typed_duplicate_last()`；不自动接入基线。没有参数的构建/验证会报告原文未定义。对先前默认选择上述规则的实现已作修正。

`chameleon.py` 使用论文 §III.E 的 `g^H0(m) PK^rho` 和适配公式；调用方必须显式提供 H0，且输出必须为规范 BLS12-381 标量，不默认选择哈希或允许与群阶不一致的模数。测试自选的 SHA-256 映射仅用于合成原语测试。密钥类型复用审查未完成，不能直接用于跨场景密钥派生。CH 双开口反例继续见 algebra-review.md。测试只证明适配等式，不证明抗碰撞安全。

## PS 和 PHC 固定基底签名

`ps.py` 分开实现论文第 4 页 §III.B 的双元素 PS 签名与重随机化，以及第 6 页 PHCFinalize 的单元素 delta_TP。两者不混用 DTO，也不将前者擅自替换为 PHC 报文字段。一般 PS 的 x、y 来自 Fq，签名及重随机化随机数来自 Fq*；Phase 0 c1、c2 来自 Fq*。第一签名分量为单位元必须拒绝；第二分量为单位元并非必然非法，按原文等式检查。

`sign_phc_scalar` 和 `verify_phc_scalar` 只处理已提供 y0 的签名等式，不生成身份映射、KTP、AF/RF、PHC 或注册记录。不实现 InitProve 中的未定义符号替换，不声称完整盲化认证或匿名性证明已完成。

公开合成数据实验：`python -m demos.memauth.ps_public_trace`。它记录公钥、原签名、重随机化签名、固定基底签名、配对操作数和篡改拒绝结果。发行密钥与随机化秘密不输出。输出的公开 y0 只属于该合成原语实验，不是实际匿名认证转录。
