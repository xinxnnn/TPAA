# A 轮启动与运行说明

本文件记录 A 轮的真实启动边界与测试方式。请先读限制再启动，避免把测试 adapter 当成生产密钥托管。

## 运行边界

- **用户密钥不受用户独立控制。** `user_credential_handler` 将 USER 密钥种子明文写入 `keys.json`；只用于本机演练和测试。响应和事件中不能回显私钥、种子、`s_ap`、陷门开口等秘密。执行器的 profile 是 `test-adapter`；不要将它标为 `user-controlled`。
- 当前仓库没有真实身份核验机构或硬件钱包接入。`identity-service` 的正式装配要求可信核验方签名的 `IdentityEvidence`；它只验证证据，不能代替核验机构。现有本地组合栈显式使用 `test_adapter=True`，继续只处理合成身份。Portal 的 `user-controlled` 入口只接受用户钱包预构造的密文 CR；当前测试执行器不能被配置成该 profile。
- 执行器只绑定一个 owner；一个 owner 一个进程、state 目录、token 和端口。只允许 loopback；token 能防远端误用，不能隔离同机恶意进程或防止同机读取 state 文件。
- 所有服务必须单 worker。challenge 是进程内一次性状态，`JsonStore` 的读改写只在进程内同步。多 worker 会破坏这些约束；启动入口会拒绝已识别的多 worker 参数/环境变量和派生 worker 子进程。
- B1 令 Portal 不再持有 TP/AP AUTH issuer 种子。Portal 仍会取得短期域 token；被控 Portal 在 token 有效期间仍可能代用户调用域服务。每请求用户签名或硬件隔离确认尚未实现。
- `phc-service` / `review-service` 当前不能从各自独立入口完整装配 TP 域。B1 socket smoke 使用真实独立 executor 进程，但 TP identity domain 在测试进程中装配；它不是 TP 拆分部署证明。
- AP 的发布证明校验与 AG2 Runtime 代码仍留在独立模块中，但当前 User Portal 主流程不开放 PUB/RUN；本阶段只验收到最终 PHC。Agent 制品、模型调用、工具连接器及独立 runtime 后续再做。

## 环境变量

### Executor（每个用户一个）

- `TPAA_EXECUTOR_STATE_ROOT`：执行器状态目录，包含明文测试密钥 `keys.json`。
- `TPAA_EXECUTOR_TOKEN`：Portal 到 executor 的 bearer token。
- `TPAA_EXECUTOR_BIND`：默认 `127.0.0.1`；仅允许 `127.0.0.1`、`::1`、`localhost`。

### Portal

- `TPAA_EXECUTOR_URL`、`TPAA_EXECUTOR_TOKEN`、`TPAA_EXECUTOR_OWNER`
- `TPAA_USER_AUTH_HSM_SEED`：**用户区** AUTH issuer seed；不是 TP/AP 的 AUTH seed。
- `TPAA_USER_STATE_ROOT`、`TPAA_USER_WORKFLOW_DB`
- `TPAA_TP_URL`、`TPAA_AP_URL`、`TPAA_PHC_URL`
- 可选认证地址：`TPAA_TP_AUTH_URL`（默认 TP URL）、`TPAA_AP_AUTH_URL`（默认 AP URL）、`TPAA_PHC_AUTH_URL`（默认 TP URL）

### TP / AP

TP identity 需要 `TPAA_V1_HSM_SEED`、`TPAA_IDENTITY_DB`、`TPAA_TP_STAFF`；AP agent 的变量由 `services/ap_side/agent_service/infra/wiring.py` 的 `InfraConfig.from_env()` 定义。仓库目前不提供完整部署用密钥生成器与跨服务启动编排；未配置时服务应拒绝启动，不能生成临时密钥冒充可用。

TP identity 的独立正式入口还需要 `TPAA_IDENTITY_VERIFIER_TRUST` 指向可信核验方公钥名录 JSON；字段和签名体见 [P0–P2 实施口径](docs/protocol-map/p0-p2.md)。没有核验机构签发的真实证据，配置该名录并不意味着已完成现实身份核验。

种子 JSON 的演练形状：

```json
{
  "tp":   {"schnorr_sk": "<hex>", "chameleon_sk": "<hex>", "root": "<hex>"},
  "auth": {"schnorr_sk": "<hex>", "chameleon_sk": "<hex>", "root": "<hex>"}
}
```

## 一键启动本地端口平台

本地启动器按 `$services` 表管理服务名称、ASGI 模块、端口和健康检查。只需在仓库根目录运行一条命令：

```powershell
.\scripts\start_system.ps1
```

也可以在 Windows 资源管理器中双击仓库根目录的 `start_system.cmd` 启动，或在 PowerShell/CMD 中运行它。首次使用前请确保已安装 Python 项目依赖和 Node.js/npm 依赖。

默认地址：

- Executor：`http://127.0.0.1:8110/healthz`
- TP：`http://127.0.0.1:8120/tp/healthz`
- AP：`http://127.0.0.1:8120/ap/healthz`
- Review：`http://127.0.0.1:8120/review/healthz`
- PHC：`http://127.0.0.1:8120/phc/healthz`
- Portal：`http://127.0.0.1:8000/healthz`
- User Web：`http://127.0.0.1:5173/`
- TP 审核台：`http://127.0.0.1:5180/`

TP 和 AP 暂时共用 `8120` 上的本地组合进程；review/PHC 依赖 TP 进程内对象，不能把它们伪装成独立 TP/AP 部署。启动器会在 `%LOCALAPPDATA%` 以外的默认路径 `D:\tpaa-run\local-stack` 持久保存演练种子、申请状态和 TP/AP 槽位绑定；可用 `-StateRoot` 指定其他目录。升级前已落盘、但因旧版本只保存在内存而丢失槽位绑定的申请，会在启动时基于已签名 CR、TP 陷门公钥及 AF 校验后恢复绑定。种子是明文测试密钥，不要提交或分享。

```powershell
.\scripts\start_system.ps1 -NoFrontend
.\scripts\start_system.ps1 -StateRoot 'E:\tpaa-demo' -NoBrowser
```

若你的电脑没有 `E:`，请选择已有盘符，例如 `D:\tpaa-demo`。用同一个 `StateRoot` 再次运行会复用同一组演练种子；不要在服务运行期间改用另一个状态目录。

关闭本脚本启动的平台服务：

```powershell
.\scripts\stop_system.ps1
```

也可以双击仓库根目录的 `stop_system.cmd` 关闭。若启动时指定了自定义 `StateRoot`，关闭时必须传入相同路径，例如：

```powershell
.\scripts\stop_system.ps1 -StateRoot 'E:\tpaa-demo'
```

停止命令会结束平台保留端口（8110、8120、8000、5173、5180）上的监听进程；请先关闭这些端口上运行的其他程序。种子、配置、日志和申请数据不会删除。若终端中的服务未由启动器托管，也可以在对应服务终端按 `Ctrl+C` 关闭。

启动日志写入 `<StateRoot>\logs`。启动器会等待各服务健康检查通过后才报告就绪；若启动失败，请先查看对应的 `.err.log`。启动服务只绑定 `127.0.0.1`，不可将此 test-adapter 暴露到局域网或公网。

该平台全部是本地 `test-adapter`。Executor 在服务器文件中持有测试密钥，**不代表用户独立控制密钥**。User Web 会自动建立仅本机、短期的测试会话，但不会自动创建申请、填入示例数据或推进任何流程；身份资料由用户手动填写，每个后续协议转换也由用户主动点击。此会话不是用户登录或身份认证。初始化详情读取本次运行中 TP、AP、用户执行器及监管 Paillier 的公开参数/公钥，不会另外生成一套与实际服务无关的 demo 密钥。TP 控制台的本地测试会话由服务端使用测试 STAFF 密钥签署一次性 challenge；模拟 reviewer 与两名 supervisor 分别使用不同密钥，私钥不发给浏览器，也不代表真实人员认证。监管 Paillier 测试密钥由本机持久化种子重现，以便重启后继续处理同一批本地测试凭证；该可重复密钥生成仅用于 test-adapter，不能替代生产 HSM/KMS。旧版本地演示曾在每次启动时随机生成该密钥，且只在内存保存 IPFS 密文；这些旧进程的历史凭证在重启后无法完成追溯。升级后新签发的凭证和密文对象可跨重启使用，本地对象文件只保存密文及取用留痕、不保存密钥。TP 控制台审核页实际调用 review-service 并自动刷新待审核队列，PHC 页只展示申请人流程产生的真实签发状态，DID 页展示 PHC 中完成 D6 的绑定索引；监管案件页连接 TPAA v1 supervision-service，可从真实 D6 DID 登记举报、经两名不同监管员签名立案、由 AP 独立验证签名后完成 R1/R2 并生成加密取证包。密文取证包只允许指定监管员调阅；案件完成封存后，指定监管员可显式解封查看身份信息（姓名、证件号等 PII），每次调阅均记录监管员和时间，接口设置 no-store；原始生物特征不显示。该解封仅用于本地演示，生产部署须接入监管员终端/HSM 的私钥解封流程并遵循适用的授权与数据保护要求。独立 proto0 did-service 的撤销与父子关系追溯仍未接入该工作台。

新签发的 PHC JSON-LD 按图示结构输出：`ASO.TPM` / `ASO.APM`、`TPA`、`APA`、`PROOF`；G3、D4、D6 详情展示的均是同一密码学对象各阶段版本。现有旧申请的简写键结构可读取并按原格式校验；新输出不会混用两种结构。`profile`、生命周期 `version` 与 `ASO.APM.AFRef` 是当前 `tpaa_v1` 的版本标识及防拼接扩展，不是随机生成的 PHC 字段。

User 流程为 INIT → G1 → TP 人工审核 → G3/G4 → D1–D6/FINAL。旧申请不会在页面载入时自动选中；新申请的 G1 回执、CR 摘要及后续阶段产物均归属于同一个申请编号。G1 的表单字段以密文 CR 提交 TP；审核队列显示脱敏字段。用户可在 G1 详情中按需查看 TP 解密后的脱敏演示结果（PII 掩码、生物信息仅列字段、照片只列类型与编码大小）；该视图要求申请所有者鉴权，明文不写入 Portal 时间线。G1 解密演示结果会说明并展示 CR 摘要和 AF 计算结果，但不会返回 H(ID) 的值；H(ID) 由协议实际计算并用于验证 AF，因身份数据低熵而可能被猜测，不适合公开展示。D4、D5 详情会分别展示 CMI 的实际输入模块及摘要、选择/PAR 摘要、最终 CMI，以及用户侧重算的 CMI、PHC 摘要、modulesDigest、AFRef、D4 声明摘要和签名验证结果；HCGen 中间链值仍隐藏。详情中的普通 JSON 摘要使用 SHA-256 和规范 JSON 编码，协议哈希采用 TPAA/v1 带长度前缀类型编码及域分离 tag。D6 完成后，本地 test-adapter 允许申请所有者显式请求 TP 解密 DID 中 Base64URL 编码的 CSCID 密文，展示其中的 AF/RF，不返回 H(ID) 或原始身份；部署环境默认关闭该接口。其它阶段也可按需查看由对应协议参与方解密/验证的安全结果，身份哈希及随机开口等秘密不展示。

User Web 可上传仅用于本机演示的 JPEG、PNG 或 WebP 测试照片（不超过 64 KiB）。照片作为 BI 字段随 G1 一起封装进发给 TP 的加密 CR；Portal 时间线和流程事件不会回显照片。仅本地 test-adapter 的 TP reviewer 详情页会预览照片，审核队列和其他部署默认不返回照片原文。当前流程没有人脸识别/照片与证件比对算法，照片本身不构成身份验证结论。请只使用合成身份和测试照片，**不要输入真实个人身份资料或真实人脸照片**。端口启动成功也不代表服务达到生产部署条件。

注意：这个 test-adapter 演示中，浏览器到 Portal、Portal 到 executor 是本机 loopback HTTP；原始表单内容在 executor 构造 CR 前会经过本地服务进程，**不是浏览器到 TP 的端到端加密**。不得因此提交真实个人信息或人脸照片。

## 各服务环境变量启动方式（手动部署）


PowerShell 示例（每个 shell 设置自己的环境变量）：

```powershell
$env:TPAA_EXECUTOR_STATE_ROOT = 'D:\tpaa-run\executor-alice'
$env:TPAA_EXECUTOR_TOKEN = '<部署生成的随机 token>'
$env:TPAA_EXECUTOR_BIND = '127.0.0.1'
$env:PYTHONPATH = '<仓库根目录>'
python -m uvicorn services.user_side.executor_service.app:app --host 127.0.0.1 --port 8110 --workers 1
```

启动后确认 `GET http://127.0.0.1:8110/healthz` 返回 `profile: test-adapter`。同机可用 `Invoke-RestMethod`，不应把 token 放进 URL、日志或截图。

## 启动本地 test-adapter TP/AP 组合

仓库提供一个仅限本机演练的组合入口，把 identity、review、phc 和 AP agent 装配在同一个单 worker 进程中。它不代表独立 TP/AP 生产部署，也不提供用户独立控密钥。

先生成一次性且持久复用的演练配置。不要把生成目录或其中的种子文件提交、上传或发到聊天：

```powershell
python scripts/prepare_local_test.py --state-root 'D:\tpaa-run\local-stack'
$config = Get-Content 'D:\tpaa-run\local-stack\local-config.json' | ConvertFrom-Json
$config.psobject.Properties | ForEach-Object { Set-Item -Path "Env:$($_.Name)" -Value $_.Value }
$env:PYTHONPATH = (Get-Location).Path
```

在同一 PowerShell 窗口启动组合服务。当前组合服务必须使用 loopback，且只能单 worker：

```powershell
python -m uvicorn services.local_test_stack:app --host 127.0.0.1 --port 8120 --workers 1
```

另一个窗口验证：

```powershell
Invoke-RestMethod 'http://127.0.0.1:8120/healthz'
Invoke-RestMethod 'http://127.0.0.1:8120/tp/healthz'
Invoke-RestMethod 'http://127.0.0.1:8120/ap/healthz'
Invoke-RestMethod 'http://127.0.0.1:8120/phc/healthz'
```

Portal 使用组合服务时，不再填写不存在的 8200/8300 地址：

```powershell
$env:TPAA_LOCAL_TEST_STACK = '1'
$env:TPAA_LOCAL_TEST_STACK_URL = 'http://127.0.0.1:8120'
$env:TPAA_EXECUTOR_URL = 'http://127.0.0.1:8110'
$env:TPAA_EXECUTOR_OWNER = '<executor owner>'
$env:TPAA_USER_STATE_ROOT = 'D:\tpaa-run\user-alice'
$env:TPAA_USER_WORKFLOW_DB = 'D:\tpaa-run\user-alice\workflow.json'
$env:TPAA_USER_AUTH_HSM_SEED = 'D:\tpaa-run\local-stack\user-auth-seed.json'
python -m uvicorn services.user_side.portal_api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

组合服务的 `/tp`、`/ap`、`/phc` 是本地测试路径；Portal 通过 executor 签名 challenge 后取得短期域 token。浏览器登录仍未实现，user-web 没有可用 user-zone 会话时会保持阻断，不要输入真实身份资料。

Portal 只有在 executor 和 TP/AP 上游完整配置可达后才能构建上下文。Vite 开发代理 `TPAA_USER_UPSTREAM` 指向 Portal（默认 `http://127.0.0.1:8000`）：

```powershell
$env:TPAA_EXECUTOR_URL = 'http://127.0.0.1:8110'
$env:TPAA_EXECUTOR_TOKEN = '<与 executor 相同的 token>'
$env:TPAA_EXECUTOR_OWNER = '<executor 公钥归属指纹>'
# 设置 Portal / TP / AP 的其余变量后：
python -m uvicorn services.user_side.portal_api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

然后在另一个终端：

```powershell
$env:TPAA_USER_UPSTREAM = 'http://127.0.0.1:8000'
npm --prefix apps/user-web run dev
```

- Reviewer queue is available only through the authenticated TP identity-service endpoint `POST /v1/applications/review-queue`; the TP web now reads live masked queue data but does not yet provide browser login. A valid reviewer bearer session must be provisioned out of band for API-level testing.
- `user-web` main workflow is implemented but blocked until a user-zone bearer session exists. There is no browser login exchange; never put executor tokens or private keys in frontend code/storage. Do not treat a manually provisioned operator token as user-controlled authentication.
- Do not start servers through automation as part of repository validation. Operators must explicitly start each service and frontend themselves.

## 对账与幂等

- Portal `issue` 先持久记录 `issuing`，出错后记录 `issue_failed`；不自动重放非幂等 TP `/issue`。用户可 POST `/api/user/v1/applications/{id}/reconcile` 对账。
- Executor 状态修改需要 requestId。同号同请求体返回首次结果；同号不同请求体返回 409。幂等记录持久化在 executor handler state 中。
- Portal 只有 GET 401 会刷新域 token 并重试一次；非幂等 POST 不会因登录刷新而盲目重放。
- AP D4 在同一原始 PACI 请求重试时重放已持久化的 PAR / recordId；同一会话更换 PACI 返回 409。Portal 本地 test-adapter 给 AP 请求 120 秒，覆盖昂贵的 D4 计算。
- D1 的 AR 密文由 AP 会话保存；Portal 时间线只展示请求号和 CMM 版本，不回传 AR 密文。AP 的只读会话接口可用于受权排障。
- 旧版 AP 会话若已标记 built、但未保存 D4 响应，仅当原用户、申请、CMM、签名模块配置均匹配且旧记录未发布时，才会使用新 recordId 重新生成 D4，并在时间线标明旧 recordId；配置不匹配或状态不完整时明确返回冲突。不要手工删除 AP 状态或记录来绕过此保护。

## 验证

```powershell
python -m pytest tests/integration/test_executor_contract.py -q
python -m pytest tests/integration/test_b1_socket_smoke.py -q
python -m pytest tests/adversarial/test_d4_statement_attacks.py -q
python run_tests.py --all
```

`run_tests.py --all` 将 pytest 风格集成测试转交给 pytest；不带 `--all` 时保留纯 Python 单元/对抗测试 runner。
