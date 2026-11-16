# 显式可执行记忆实验

用户批准的配置实现于 `crypto/memauth/executable_profile.py`；所有函数调用都是显式选择，没有将抽象基线自动切换到该配置。

H0/H1/H2 使用独立域标签和无偏拒绝采样；标量使用 32 字节大端。KDF 通过 keyed HMAC 扩展并拒绝零，PRF 输出限制在调用方的 Zn，支持大于单个 SHA-256 输出的 Paillier 模数。PRF 参数中的字段须显式结构化/编码，不把原文拼接替换为含糊字符串。此配置是实验实例化，不继承未审查的安全证明。

`synthetic_macro.py` 接受按顺序给出的五元字符串事件，依 H2 计算摘要，使用已确认 Keccak/Merkle 实验配置，并按原文宏节点公式求 x/y。APPEND 校验旧开口、PA 密钥、旧点，适配 CH 并返回新对象。它不排序事件、不猜测原文时间格式，也不把随机演示事件称为审计证据。

`synthetic_memory_graph.py` 将每个 `(节点类型, 节点ID)` 作为独立图节点。同一节点重复引用不重复计数；每个新子图对宏节点的共享节点数作为显式合成邻接频次。评分和选择可供前端检查，平局选择 UTF-8 ID 字节序最小者。

运行生命周期（SRS 至少 degree=4）：

```powershell
python -m crypto.memauth.setup_experiment --degree 4 --output memory-experiment-srs.json
python -m demos.memauth.memory_lifecycle --srs memory-experiment-srs.json
```

输出真实群承诺、APPEND 根变化、CREATE 约束验证及 G2 见证；不输出 skPA、sUser、theta、多项式系数或 CH 开口。y0 和初始事件为明确标注的合成输入，尚未执行 PHC 注册。InitSync 仅计算见证，没有伪称 PA/SA 完成同步；Bootstrap 和连续认证未执行。
