# 平台颁发 PA 的集成入口

个人智能体以实际 TPAA 申领流程为身份来源。接受 FINAL 后显式发布制品，再启动 Runtime；不以独立演示 DID 代替平台身份。

Portal 现在开放 PUB/RUN 动作，AP 复核接受回执、发布证明、PHC 公开签名、DID、CMI、模块及构建摘要后，使用现有身份守卫和 ToolGateway 构造真实 AG2 Agent。用户页可调用同一 Runtime；AP 再次检查 owner、吊销状态和运行证明时效。内容摘要作为未来 MemAuth 事件输入保存在运行内存，不默认保存任务明文。

申请 → FINAL PHC → AP publication → Runtime 的 DID/phcDigest/CMI/manifestDigest 在后端关联。AG2 prompt 不持有凭证或密码秘密。集成测试从实际申领流程推进到发布、构造和任务调用，验证 Runtime DID 和 PHC 摘要与本申请最终凭证相同。

当前模型是 ag2.testing.TestConfig，实例是真 AG2、回复为固定测试结果；不是远程模型推理。Runtime 内存随进程退出丢失，重启后须重新构造，不能把旧持久状态当作仍在线实例。当前前端尚未提供该重建动作。

MemAuth 状态显式 not-enrolled：下一阶段需由受控注册器在此平台 Runtime 上建立独立 MemAuth 凭证与密钥状态，而非重新创建未签发 PA。原本独立 ag2_memory 演示仅用于适配测试，不是平台生产入口。此前 RUNNING.md 中“主流程停在 FINAL”的描述已被本增量取代；其它部署边界仍适用。
