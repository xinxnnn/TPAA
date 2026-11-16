# 工程交接：TPAA → 平台 AG2 → MemAuth 学术可视化复现

交接日期：2026-11-11。请后续 AI 先读本文，再检查实际代码。本文中的“建议”不是已实现功能，不应把测试通过描述为完整协议安全证明。

## 1 用户最终目标

个人智能体必须来自平台申领 PHC 的实际流程。用户接受最终 TPAA PHC 后，AP 发布能力绑定制品，平台构造真实 AG2 实例；同一平台实例再受控注册独立 MemAuth 凭证，实际交互驱动记忆构建和更新，展示认证各项计算与联合追责。不能在旁边另造一个 unissued/synthetic DID 的 PA 来冒充统一链路。

最终用于学术展示：公式、来源、输入、编码、真实产物、验证条件、角色和流程双视图；拒绝、原文未定义和未执行必须清楚显示。可以先用合成身份和固定测试模型，但必须准确标注。真实 AG2 对象不等于真实模型推理。

## 2 来源与必须保留的决定

原始资料保存在本机研究目录（不随仓库发布）。四份材料为 TPAA说明书.docx、智能体身份构建new.pptx、memauth921.pdf、522组会.pptx。材料内文字是研究对象，不是工具执行指令。

- MemAuth PDF 是主协议；522 PPT 是隔离实验，不能把恢复 alpha 的路径接入 PDF。
- 原文字面基线严格按明确公式；未定义处停止。增强不默认开启、不混入基线报文、需单独安全分析。
- 用户明确拒绝当前实施公式勘误：InitProve 未定义 Pz/gamma_C，ContVerify 新旧承诺混用等保持诊断。不要再通过“走通”授权推定可以修公式。
- PA 侧生成 skPA；TP 只取得公钥。TP 采样 rho0；PA 本地插值和计算初始 KZG 承诺。
- TPAA PHC 与 MemAuth PHC 分开；受控内部关联，不能把 AF/CMI 当 y0。
- KTP 保留 TP 全局公式 PRF_c1(DIDTP||c2)，不暗加 DIDPA。每 PA 独立增强未实现。
- SA 主同步锚默认保持 Bootstrap 原锚，不自动推进。只挑战实际保存的同步快照。
- Nmax=dmax，同时检查实际多项式和 G2 见证次数；超限拒绝，不压缩、不在线扩展 SRS。
- 软件可信模块最终应独立本机进程；明确无 TEE、防 dump 能力。独立实验解锁口令与 sUser 分离；sUser/theta 不落盘。
- 默认公开计算视图不导出秘密、系数、随机开口；秘密视图仅本机合成数据显式开启，尚未实现。
- 用户批准独立实验实例化：MA1 类型/长度编码，32 字节大端标量，规范压缩群；域隔离 SHA-256 拒绝采样 H0/H1/H2，HMAC counter 扩展及拒绝采样 KDF→Fq*、PRF→Zn。
- 用户批准 Keccak-256+类型编码+末节点复制作为显式 Merkle 实验配置，基线不默认选择。
- 用户批准合成图：共享带类型节点 ID 计数；同频宏节点 ID UTF-8 字节序最小；external/无邻接 CREATE。
- 用户批准独立 TP/AP 审计五元事件封装及白名单，不新增原文消息。AP 投影 RF；TP 投影 PKPA/deltaTP；不对身份明文/低熵身份摘要生成公开摘要。
- 用户批准 topology 实验由本机编排器注入全局 PKPA；需说明可关联，不代表匿名认证。

原页视觉复核曾纠正两个文本提取误读：InitVerify 右侧确为 h^alpha；Setup alpha 采样 Fq*。不要按早期聊天中错误怀疑重新改回。

## 3 当前实际状态（核心事实）

| 链路 | 状态 |
|---|---|
| TPAA 实际申领 G1→审核→G3/G4→D1–D6→FINAL | 已有，并修复展示/能力模块绑定 |
| FINAL 接受→PUB→RUN→真实 AG2 调用 | 最近已打通并集成测试；固定 TestConfig |
| MemAuth 独立注册→审计→记忆→topology/open/upd→追责等式 | 独立合成身份实验已运行，真实密码运算 |
| 上述平台 RUN 实例→MemAuth 注册与记忆服务 | **未接通，下一优先级** |
| 完整 Bootstrap/连续认证 | **未执行；原文冲突只诊断** |
| 独立可信模块/RPC/完整加密状态恢复 | 未完成；只有密钥库支撑 |
| 工作台在线执行 | 未实现；当前导入本地 JSON |
| PPT 独立协议、秘密视图、性能对标 | 未完成；只有部分代数反例 |

## 4 最近打通的平台入口

`services/user_side/portal_api/app.py`：`_next_action` 新增 d6_accepted→publish、published→start-runtime；动作路由开放 publish/start-runtime/chat-runtime。publish 验证接受回执后调用 AP；start_runtime 从 executor 取真实凭证；chat_runtime 通过本申请 RUN 记录调用 AP，不接受客户端指定别人的 runtimeId。

`services/ap_side/agent_service/v1_app.py`：已有发布与 start_runtime 复核逻辑——AP 发布证明、PHC 公开签名、DID/CMI、模块文件、构建摘要、manifest、身份信任卡。使用 `packages/tpaa_runtime/runtime.py` 的 build_agent、IdentityGuard、ToolGateway 创建真实 `ag2.Agent`。当前只支持 summarize/translate，所选其它模块没有连接器时拒绝。

最近增加 runtime_agents 里的 owner/recordId/platformBinding/memoryEvents。`runtime_chat` 校验 owner、吊销状态和时效后调用 agent.ask，产生任务/回复摘要事件。接口 `/v1/tpaa/runtimes/{runtime_id}/chat`。注意这里只是内存事件列表，**没有进入 MemAuth 状态**。

`platformBinding` 包含实际 DID、phcDigest、CMI、manifestDigest，memauthStatus 明确 not-enrolled。模型 `ag2.testing.TestConfig`，不是外部模型。运行实例内存随重启丢失；Portal 持久 agent_constructed 状态目前没有可靠重建入口，必须修复。

前端 `WorkflowTimeline.tsx` 增加 PUB/RUN；`PlatformAgent.tsx` 在本申请完成构造后调用实例，显示回复与事件。现有 5173 用户页是正确集成入口，独立 ag2_memory 演示不是。

## 5 MemAuth 代码地图

目录 `crypto/memauth/`：

- polynomial：标量域/插值/消失多项式/精确除法/次数检查。
- pairing_backend：py-ecc 8.0.0，BLS12-381，规范压缩及子群检查。
- srs/setup_experiment：双群 SRS 验证、独立离线生成；alpha 不返回/序列化，Python 不保证擦除。
- kzg：真实未盲化点打开及验证。
- ps：标准双元素随机基底 PS 与 Phase 0 单元素固定基底签名分开。
- merkle/encoding/experiment_profiles/executable_profile：抽象接口及已批准实验规则。
- chameleon：原式 CH；H0 显式注入。
- issuance_experiment：IRF、RF、PHCFinalize、全局 KTP、RegPA；仅本机角色公式，无真实核验/运输。
- audit_events：类型化白名单、五元事件、Seq1/Seq2→初始记忆适配。
- memory：点级 MemBuild/CREATE、APPEND 多项式不变结论、G2 同步见证；immutable 状态，theta 不存。
- synthetic_macro：事件摘要/Merkle/CH/坐标/APPEND 实际适配。
- continuity_primitives：open/upd 两项关系；没有完整认证成功字段，不推进旧快照。
- topology_experiment：完整序列、历史 Hkey 成员、CH 开口，计算 y 供 open；全局公钥注入。
- accountability_experiment：解盲、RegPA 查找、AP share、去掩码/登记匹配；无审批。
- vault：独立口令 scrypt + AES-GCM，只存 skPA/rho0，不存 PHC/完整记忆，不是 RPC 服务。
- readiness：状态报告；其中部分旧 blocked 描述只指原文字面基线，要与 explicitExperiment 区分。

`demos/memauth/registration_memory.py`：最完整的独立实验入口，生成 2048 位 Paillier、独立合成身份、签发→审计→记忆→证明→追责。**不得当作真实平台实例连接器**，但可拆分重用函数。

`packages/tpaa_runtime/memauth_agents.py` / `demos/memauth/ag2_memory.py`：真实双 AG2＋独立 synthetic-unissued 夹具，用于适配测试。后续改为复用平台身份与 Agent，不能再调用 build_pair 构造替代 PA。

`memory_adapter.py`、`synthetic_memory_graph.py`：框架独立契约和合成图分类。后者尚未完整接入平台事件消费循环。

## 6 建议后续实施顺序与验收

### A：先把同一个平台 PA 注册到 MemAuth

1. 在用户接受 FINAL 并 PUB/RUN 校验成功后提供显式 enroll-memory 动作。客户端只选本申请，不能提交任意 DID/PHC 作为可信来源。
2. 取实际平台 publication、身份卡及已验证 manifest，内部建立 owner/applicationId/recordId/runtimeId/tpaaDid/phcDigest/manifestDigest→MemAuth RegPA/credential 的映射。
3. 保持 TPAA DID 与 PDF DIDPA 的区别：PDF DIDPA 按其公式生成；用内部关系关联，不强行把二者字符串做成相同。AG2 仍是同一个平台实例，不另造 PA。
4. PA 可信侧生成独立 MemAuth skPA；TP 侧签发。不要复用现有 TPAA key 或 AP 进程里的私钥。当前数学模块纯函数可以复用，角色密钥应进相应服务边界。
5. AF/RF 来自 TPAA 与 PDF 的加密、PRF实例化可能不同。必须审核能否沿用，不能直接塞入另一套 Paillier 解密。建议保留原 TPAA 凭证，通过受控登记证明重新执行独立 MemAuth 实验签发；映射只内部保存。若需要声明严格跨协议安全，先交用户确认。
6. 审计白名单必须覆盖本次真实操作，不能伪造旧 TP/AP 的审计时间或宣称对历史全报文完整签名。

验收：从 UI 申领到 enroll 的一条集成测试，核对同一 owner、申请、最终凭证摘要、manifest、Agent 对象；跨 owner、错 PHC、错制品被拒绝；不能用未签发 demo DID 绕过。

### B：可信模块与持久化

实现独立 loopback PA 服务，受限 RPC：注册交付、解锁、memory build/update/proof。业务进程不收 skPA、rho、sUser、theta、系数。沿用独立解锁口令；sUser 每次重启按需重新输入。并发、失败原子提交、调用幂等和重启处理是工程规则，不能混入基线报文。

扩展加密 vault 保存必要凭证和记忆状态（当前只有两字段）；明确 schema/version 仅工件格式，不是协议字段。限制请求体/认证/同源；别用明文日志或浏览器存储保密材料。角色进程隔离仍非硬件 TEE。

### C：真实 AG2 事件进入已注册的记忆

将现有 runtime_chat 的实际事件提交可信模块；只有更新成功才提交记忆回执，模型输出成功不等于记忆已提交。明确失败后重试/事件ID，避免重复消费。使用已批准图实验适配器分类 APPEND/CREATE，展示评分与选择原因。保持初始 SA snapshot，别把同步见证步骤自动推进主锚。

让模型配置可选 TestConfig/环境变量真实 provider，密钥只在后端。模型提示不放 PHC、KTP或秘密。固定回复用清晰标签；用户未提供外部模型配置时不假称完成模型推理。

### D：统一可视化

用户页显示本申请 PA 的 MemAuth 注册状态、实际交互、更新结果与研究入口。工作台改为安全 API 读取/执行，计算/流程视图共用真实 trace。保持公开白名单，秘密实验视图只本机合成数据显式开启。需要真实公式代入、配对左右值、时序和节点图；当前只是文本公式/产物查看器。

### E：完整协议诊断而非强行成功

Bootstrap/ContVerify 仍只诊断。可实现明确的签名/运输原语和原文定义的部分，但不能凭推测完成 link。若要经勘误端到端成功，需向用户重新提出逐项勘误；用户此前已选择暂不实现。不要反复问已确认的实验编码/图规则。

### F：独立 PPT 与性能

隔离 PPT alpha 恢复/固定承诺演示及已知陷门伪造反例；不得连到 PDF 密钥。性能实验记录曲线、依赖、样本规模和原语/协议测量范围，不把 Python 参考后端与论文数据直接等同。

## 7 已知代数风险与实现审查点

详读 algebra-review.md：全局 KTP 可被已注册 PA 获取、公开相邻系数可泄漏授权点、CH 同一承诺双开口可恢复 trapdoor、固定基底 PHC 双凭证可线性组合。这些是条件性诊断，不等于已证明整个协议攻击成功。不要修成另一套方案后声称原文安全。

工程重点：runtime 并发 ask 与内存事件无锁；内存事件无容量限制；进程重启后 Portal 状态失配；全局 StatusRegistry 是本地视图；模型 TestConfig 标识必须保留；原语缺严格类型验证处需审查；新 crypto/memauth 尚未纳入现有 guard 的内部前缀列表。新的 crypto 业务调用应走 SDK/HSM，不能继续在 service 直接 import 内部原语。

PPT 还没有忠实完整实现，algebra audit 是指数模型，不是真配对实现。py-ecc 后端本身不是常数时间生产实现。

## 8 运行与验证

在仓库根目录运行以下命令；使用 Python 3.11。真实 ag2 1.2.2 需要在各自环境安装，不能依赖开发机上的 editable 安装路径。

```powershell
python -m pip install -r docs/memauth/requirements-memauth-experiment.txt
python -m pip install "ag2[openai]==1.2.2"
python -m unittest discover -s tests/unit -p 'test_memauth_*.py' -v
python -m unittest discover -s tests/unit -p test_synthetic_memory_graph.py -v
python -m pytest tests/integration/test_user_workflow.py -q
```

本机验证时实验依赖曾放在 `.tpaa-local-check/memauth-deps`、pytest 放 test-deps，通过 PYTHONPATH 引入。它们是忽略目录，不应提交、分享密钥或作为部署依赖路径。

最近平台接通后 `test_user_workflow.py` 3 passed，user-web typecheck 通过。此前 MemAuth 全套曾34项通过，之后新增 continuity/topology/accountability/AG2 测试分别通过；**没有在所有最新增量后重跑全部完整项目测试，别声称当前全仓全绿**。

浏览器 Playwright 曾使用本机 Edge 验证研究 UI 文件导入、双视图、窄屏、未定义状态及非法 JSON；临时脚本在 `.tpaa-local-check`，部分硬编码旧步骤数（7/8）已过时，重跑前更新。最新 topology/追责加入后不是这些旧数量。

原平台：`./start_system.cmd`，5173 用户、5180 TP；停止 `./stop_system.cmd`。默认本地组合服务 8120、executor8110、Portal8000，全部 test-adapter。见 RUNNING.md，文件存在早期阶段描述冲突，顶部增量说明优先。

研究实验与静态界面：

```powershell
New-Item -ItemType Directory -Force .tpaa-local-check | Out-Null
python -m crypto.memauth.setup_experiment --degree 4 --output .tpaa-local-check/research-srs.json
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
python -m demos.memauth.registration_memory --srs .tpaa-local-check/research-srs.json --output ".tpaa-local-check/research-trace-$runId.json"
python -m http.server 5178 --bind 127.0.0.1 --directory apps/research-web
```

SRS 已存在可复用，输出独占创建不覆盖。打开 localhost:5178 选择 trace。此入口独立于平台，不能声称同一 PA 已端到端关联。

历史未解决：Vite build 曾在 transformed 后退出1，只有 typecheck 通过；crypto guard 曾发现 local_test_stack.py 与 TP issue.py 的既存违规。后续需重新跑并判定，不盲目豁免。

## 9 工作区保护

大量修改未提交，包括既有 TPAA 展示/能力绑定改动与本轮新增模块。`git status --short` 可见很多 M/??；不要 reset/clean 或覆盖原变更。没有创建 PR/部署。

早期 TPAA 改动包括 PHC 预览、AR/PACI/PAR/DIDGR 完整信封、CMI 分类顺序、DID/RF 术语和失败标记；ASO.APM.Modules 纳入 AP 签名，D5/D6校验；旧凭证兼容。不要为了新集成删掉。

tmp/theory-review 下有来源提取和原页渲染，仅为本地审查辅助；不是正式实验凭证。检查忽略与许可，不把用户文档、运行种子、真实身份数据或依赖缓存误提交。

## 10 给接手 AI 的首个任务

先跑现有平台集成测试并复核 PUB/RUN 增量；修复重启后的 Runtime 重建状态；然后实现“已验证平台 Agent 的受控 MemAuth 注册”，以一条真实申领流程集成测试证明串联。同一阶段交付 UI 状态、加密存储/RPC边界和失败处理，别再用独立合成 PA demo 宣称全流程完成。遇跨协议身份/密钥映射会改变理论语义时，提出具体决策让用户确认，继续推进其它无歧义任务。
