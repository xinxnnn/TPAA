# 真实 AG2 实例与记忆接入

已实现真实 `ag2.Agent` 的 PA/SA 双实例。PA 接收合成研究任务、调用模型生成请求，SA 接收该请求并调用模型回应；宿主把两次实际输出摘要转换为五元事件，接入 APPEND/CREATE、topology 和 open/upd 验证。没有用普通 Python 角色对象冒充 AG2。

该入口是独立运行时接线实验：初始身份与记忆为明确标注的未签发合成夹具，不声称已绑定真实 TPAA/MemAuth 凭证。此前的 registration_memory 入口仍用于真实密码运算的签发实验。二者还未合并为持久化角色服务。

安装（Python 3.11；当前验证版本 ag2 1.2.2）：

```powershell
python -m pip install "ag2[openai]==1.2.2"
python -m pip install -r docs/memauth/requirements-memauth-experiment.txt
```

在项目根目录设置模型配置；密钥只放当前进程环境，不写入代码、凭证或模型提示。模型请求会发送到指定服务并可能产生费用，任务只使用合成数据。

```powershell
$env:MEMAUTH_MODEL_API_KEY = '<你的模型服务密钥>'
$env:MEMAUTH_MODEL = 'deepseek-chat'
$env:MEMAUTH_MODEL_BASE_URL = 'https://api.deepseek.com/v1'
python -m demos.memauth.ag2_memory --srs .tpaa-local-check/research-srs.json --output .tpaa-local-check/ag2-memory-trace.json
```

已有 SRS 至少 degree=4；输出拒绝覆盖。记录包含真实 AG2 类标识、事件摘要、更新前后承诺及配对检查。默认不导出模型回复正文、模型密钥或密码秘密。内容摘要不保证低熵消息隐私，记录仅供本机合成实验。完整认证仍未执行；此 JSON 当前独立于 registration_memory 工作台导入格式。

验证使用真实 AG2 请求循环对接本机 OpenAI-compatible 固定回复端点，然后接入真实群运算和记忆证明。这验证框架/密码接线，不证明远程模型效果；未提供模型密钥时不自动尝试外部推理。

```powershell
python -m unittest discover -s tests/unit -p test_memauth_ag2.py -v
```
