# MemAuth 学术复现工作台

独立的静态首版，无需修改现有四个业务前端或安装 Node 依赖。不接收密钥，不持久化输入，无远程请求；从文件导入真实后端生成的合成实验记录。页面不验证 JSON 文件真实性，不在浏览器执行密码学复验。

在仓库根目录，安装已记录的实验依赖后：

```powershell
python -m crypto.memauth.setup_experiment --degree 4 --output .tpaa-local-check/research-srs.json
python -m demos.memauth.registration_memory --srs .tpaa-local-check/research-srs.json --output .tpaa-local-check/research-trace.json
python -m http.server 5178 --bind 127.0.0.1 --directory apps/research-web
```

浏览器访问 `http://127.0.0.1:5178`，选择生成的 research-trace.json。Setup/trace 文件采用独占创建，不覆盖旧文件；重跑时使用新文件名或显式选择已有 SRS。不要把整个仓库作为静态服务目录。

初版覆盖：配置与 SRS 标识、全局约束检查、算法导航、原文位置、公式、实际公开产物、审计编码、记录导出和窄屏布局。没有执行按钮、秘密实验视图、完整证明可视化和性能对标；文件导入仅作为可运行的第一步，后续接入可信服务时扩展。

按用户选择提供计算/流程双视图：流程视图以同一导入记录展示步骤状态，角色及产物流转是明确标注的本机实验展示注释，不冒充网络消息或可信交付。每步可跳转对应计算详情。两种视图均保留未定义/未执行状态，不影响或重跑计算。

Bootstrap/连续认证保留原文诊断而未执行，明确显示原文未定义；不可根据其它步骤通过宣称完整协议认证成功。联合解掩码检查是本机仿真角色的等式实验，不是已授权的追责请求。
