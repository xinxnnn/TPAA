# TPAA 平台 · 工程代码

与《TPAA说明书》及平台方案配套的工程实现。下方十一步记录的是早期 `proto0` 的建设里程碑；
当前身份主流程已采用安全勘误后的 `tpaa_v1`，由 Portal 编排 G1→FINAL，并保留本地演练的发布/运行入口。
`proto0` 与 `tpaa_v1` 的实现和安全结论不得混用；当前可运行环境仍是 `test-adapter`，详见
[运行边界](RUNNING.md)与 [P0–P2 实施口径](docs/protocol-map/p0-p2.md)。历史“164 项测试”
不代表当前全仓测试结果。

## 当前进度

| 步骤 | 状态 | 内容 |
| --- | --- | --- |
| 1. 密码层地基 | ✅ 完成 | `crypto/primitives/`（5 个原语 + 21 项测试，含 11 项对抗用例） |
| 2. PHC 引擎 | ✅ 完成 | `crypto/phc/` —— 签发(G3)、算法1(AP 驱动)、算法2(TP 驱动) + 8 项证明测试 |
| 3. 派生引擎 | ✅ 完成 | `crypto/derivation/` —— 子体 AF 封父 DID、上溯到根、级联失效 + 7 项测试 |
| 4. 加密信封 + IPFS 方 | ✅ 完成 | `crypto/envelope/` SecInfo 信封 + CID 保护；`services/ipfs/storage_service/` 第五方存储（只见密文、不持密钥、取用留痕）+ 9 项测试 |
| 5. HSM 适配 | ✅ 完成 | `crypto/hsm/` —— SoftHSM（TP/AP 双域隔离，私钥不出实例，可替换为真实 HSM/KMS）+ 5 项测试 |
| 6. 越权静态卡口 | ✅ 完成 | `crypto/guard/` —— CI 静态检查，越权调用密码学即失败 + 7 项测试 |
| 7. 后端服务骨架 | ✅ 完成 | `services/` —— 按 User/TP/AP/跨域/IPFS 五方组织的服务代码 + 共享包 + contracts 占位 + 6 项测试 |
| 8. 前端 | ✅ 完成 | `apps/` —— user-web / tp-web / ap-web / ops-web + shared/，19 个页面；`scripts/check_frontend_boundary.py` 边界卡口 + 13 项测试 |
| 9. 陷门收口 | ✅ 完成 | 引擎改 HSM 注入式（私钥/陷门不进调用栈）+ `PublicChameleon` 公开句柄 + guard R4（`.forge(` 两文件白名单）+ 14 项收口测试 |
| 10. 业务落地 | ✅ 完成 | `services/ap_side/agent_service/` —— 申领/派生/找回/清扫 4 条用例、`CapabilityPort` 4 个动作（含**算法1 由 AP 自己做**）、HTTP 层与错误语义分层、启动自检、`scripts/verify_localstore.py` 巡检；**「申领 → 签发 → 落 localstore」端到端跑通**（131 项测试，含 27 项真起 HTTP 的集成测试） |
| 11. 追溯链贯通 | ✅ 完成 | 六个服务同时落地 —— `services/tp_side/did_service`（号码簿 + CSCID 封存/受控揭示）、`services/tp_side/supervision_service`（受理/立案/协查/揭露/取证）、`services/cross_domain/coordination`（TP↔AP 唯一通道）、`services/cross_domain/policy_service`（吊销令 + 级联 + 广播）、`services/cross_domain/audit_service`（哈希链审计 + 取证导出）、`services/ap_side/lifecycle_service`（承接吊销 + 协查应答 + 找回编排）；`crypto/hsm/supervision.py` 监管 Paillier 密钥句柄；**「举报 → 立案 → 协查 → 揭露 → 取证 → 吊销 → 停运」端到端跑通**（164 项测试，含 42 项真起 HTTP 的集成测试） |

## 跑测试

```bash
python run_tests.py                   # 单元 + 对抗（不需要第三方包）
python run_tests.py --all             # 再加集成（需 fastapi + httpx）
python demos/personal_agent/demo_derive.py        # 派生链演示（主 → 子 → 追溯 → 级联）
python demos/personal_agent/demo_trace.py         # 追溯链演示（举报 → 立案 → 揭露 → 吊销 → 停运）
python -m crypto.guard .              # 越权静态卡口（CI 用，发现越权退出码 1）
python scripts/check_frontend_boundary.py   # 前端边界卡口（CI 用，发现越界退出码 1）
python scripts/verify_localstore.py --root <库> --hsms <种子>   # localstore 巡检（见步骤 10）
python scripts/gen_services_skeleton.py [--force]    # 生成/重建 backend 骨架
python scripts/gen_frontend_skeleton.py [--force]   # 生成/重建 frontend 骨架
```

集成测试与巡检需要 FastAPI + httpx / 依赖隔离 venv：

```bash
C:/Users/zhouz/.workbuddy/binaries/python/envs/default/Scripts/python.exe run_tests.py --all
```

缺依赖时集成测试会记 `[SKIP]` 而不是伪装成通过 —— 「没测」不该看起来像「测过了」。

不需要安装任何第三方包 —— 核心密码层与骨架（除 FastAPI 装配基类做惰性导入外）只用标准库，便于审计与移植。
前端的 Python 侧（生成器、边界卡口、测试）同样零依赖；只有真正要 `npm run dev` 时才需要装前端依赖
（`cd apps && npm install`，详情见下节）。

## 已完成：`crypto/primitives/`

| 模块 | 内容 | 关键点 |
| --- | --- | --- |
| `group.py` | secp256k1 群运算 | **Montgomery ladder + 常数时间选择**，两条分支都算再选择，执行路径与私钥比特无关；Jacobian 坐标避免逐次模逆 |
| `schnorr.py` | 签名 / 验签 | 挑战值 e 绑定 `R ‖ pk ‖ msg`，防签名延展 |
| `paillier.py` | 加法同态加密 | n 默认 **3072 bit**；模逆用拓展欧几里得（n 是合数，不能用费马小定理） |
| `chameleon.py` | 变色龙哈希 + 陷门碰撞 | 整套方案的枢纽：改内容而哈希值不变 |
| `hashchain.py` | 哈希链 HCGen | 保留逐层中间值，支持增量比对与故障定位 |

## 已完成：`crypto/phc/`（第 2 步，方案核心）

```
AF      = CH_TP( H(ID) ‖ τ ‖ CRF ‖ APCH ‖ parent_did )
APCH    = CH_AP( APM ‖ APA )
CHproof = Sign_TP( TPCH ‖ APCH )
```

| 动作 | 谁做 | 谁的字段 | 哈希值 | 是否需要对方 |
| --- | --- | --- | --- | --- |
| 签发 (G3) | TP | TPM | — | — |
| **算法1** | AP | APM | **APCH 不变** | **不需要 TP** |
| 算法2 | TP | TPM（写 DID） | TPCH 变，TP 自己重签 | 不需要 AP |

**算法1 是本方案最核心的密码学创新**——AP 改了内容，TP 的签名继续有效，且 TP 全程不参与。
`tests/unit/test_phc.py::test_algorithm1_ap_update_keeps_tp_signature_valid` 把这件事钉死了：
断言 APCH / TPCH / AF / CHproof **四项全部不变**，且校验通过。

## 已完成：`crypto/derivation/`（第 3 步）

```
AFᵢ = CH_TP( H(ID) ‖ τᵢ ‖ CRFᵢ ‖ APCHᵢ ‖ DID₀ )
                                        ↑ 父 DID 构造时封进锚定因子
```

| 能力 | 函数 | 说明 |
| --- | --- | --- |
| 派生骨架 | `derive_child_phc` | 子体必须有**自己的** APCH（不能复制父的） |
| 封印 DID | `seal_child_did` | TP 写入唯一 DID 并重算 AF |
| 归属校验 | `verify_lineage` | 改 parent_did → AF 锚定失败 |
| 上溯 | `trace_to_root` | 子 → 父 → … → 主；**成环时能停下来** |
| 级联失效 | `cascade_revoke` | 主吊销 → 所有后代即时失效 |

`DerivationRecord.confirmed_by_user` 是**授权闸门**：未确认的派生视为非法，
不得进入生成阶段（对应"每次派生必须手动确认"）。

## 已完成：`crypto/envelope/` + `services/ipfs/storage_service/`（第 4 步，IPFS 第五方落地）

```
G2：seal_secinfo()  → 密文信封 → 上传 IPFS → CID → protect_cid() → ECID
R2：recover_cid()   → CID → 从 IPFS 取回 → unseal_secinfo() → BI / PII
```

| 模块 | 内容 | 关键点 |
| --- | --- | --- |
| `envelope/kdf.py` | HKDF 同构的 KDF（HMAC-SHA256 extract-expand） | 种子材料分而治之，任一单独推不出密钥；生产建议换 `cryptography.hkdf` |
| `envelope/cipher.py` | encrypt-then-MAC（哈希 CTR 流 + HMAC-SHA256） | 零依赖可审计；生产建议换 AEAD（ChaCha20-Poly1305 / AES-GCM） |
| `envelope/sealinfo.py` | SecInfo 信封 + CID 保护 | **ECID**：CID 也加密，IPFS 链上绝不出现明文 CID（红线 17） |
| `services/ipfs/storage_service/storage_service.py` | 第五方存储服务 | 诚实但好奇模型：只见密文、不持密钥、不解析内容；每次取用留痕（红线 18） |

这是 **IPFS 作为独立第五方** 的可运行骨架：它拿到的永远是密文，`self_check()` 证明它根本没有存密钥的字段。
`tests/unit/test_ipfs.py` 9 项把这件事钉死：G2→R2 全链路、密文≠明文、篡改即检、错误密钥失败、
ECID 不泄 CID、IPFS 不持密钥/明文、取用必留痕、pin 防 GC。

## 已完成：`crypto/hsm/`（第 5 步，HSM 适配）

| 模块 | 内容 | 关键点 |
| --- | --- | --- |
| `hsm/base.py` | HSM 抽象接口 | 对外只暴露**能力**（签名、变色龙碰撞），不暴露**原材料**；双域标签用于越权检查 |
| `hsm/soft.py` | 软件实现 SoftHSM | TP/AP 两套独立密钥；`__getstate__` 剥离私钥，序列化绝不泄漏；反序列化后失去陷门 |
| `hsm/__init__.py` | 导出 + 生产替换点 | 生产把 `SoftHSM` 换成真实 HSM/KMS 适配，上层接口不变 |

HSM 层回答了红线 1 的"可强制性"：把原始密钥关进实例，上层未来只持句柄而非密钥。
`tests/unit/test_hsm.py` 5 项钉死：TP 签名验签、TP/AP 密钥独立、变色龙碰撞保值、私钥不在 pickle 中、反序列化失陷门。

## 已完成：`crypto/guard/`（第 6 步，越权静态卡口）

| 模块 | 内容 | 关键点 |
| --- | --- | --- |
| `guard/checker.py` | AST 静态扫描 | 四条规则：R1 原语层仅 crypto 内可用、R2 内部实现仅 crypto 内可用、R3 业务层不得自建加密、**R4 `.forge(` 只许出现在两个白名单文件** |
| `guard/__main__.py` | CI 入口 | `python -m crypto.guard .` 发现越权即退出码 1，可接 CI |
| `guard/__init__.py` | 导出 | `scan_text` / `scan_dir` / `Violation` |

服务目录统一使用 Python 可导入的下划线命名；HTTP 路径、服务 ID 和协议字段仍保持原有连字符形式。
任何业务代码越权 `import` 密码学内部、或在业务层自建 encrypt/decrypt，都会被卡口拦下。
`tests/`、`demos/`、`crypto/` 自身豁免 **R1–R3**（`demos/` 在 R4 上不豁免，见下）；
当前项目扫描 **0 违规**。
`tests/unit/test_guard.py` 12 项钉死：R1/R2/R3/R4 拦截 + hsm 入口放行 + tests 豁免 + crypto 内部合法 + 项目现状干净。

## 已完成：`crypto/sdk/`（衔接层，第 7 步前置）

上层调用密码学的**唯一受限入口**。guard 仅放行 `crypto.sdk` / `crypto.hsm`，业务层直连内部实现会被 CI 拦截。

| 模块 | 内容 | 关键点 |
| --- | --- | --- |
| `sdk/__init__.py` | 聚合导出 + 演示工厂 | 重新导出 PHC/派生/信封引擎函数 + `SoftHSM`；`make_demo_hsm()` 演示工厂（仅测试与本地演练） |
| `sdk/phc.py` `sdk/derivation.py` `sdk/envelope.py` | 各引擎的受限转发 | 禁止业务层绕过的"合规收口" |

跨域要句柄就调 `hsm.public_chameleon()` —— 它只给出公钥，算得出值却改不了内容。
（这里曾经有个 `demo_chameleon()`，会把**含陷门**的内部对象原样交出去，等于把 AP 的改写权送给协程方，
已在第 9 步删除；跨域只剩 `public_chameleon` 一个出口。）
`tests/unit/test_sdk.py` 3 项钉死：上层**只经 sdk**（不 import 任何内部）即可走完签发 / 算法1 / 算法2 并校验、
公开句柄里搜不到任何密钥对象、信封往返。

## 已完成：`services/` 四方骨架（第 7 步）

按责任方分 15 个服务，每个服务遵循 §7.2 分层（`api` / `domain{entities,usecases,ports}` / `infra` / `crypto_client` / `events` / `tests`）：

- **user-side**：`portal-api`、`order-service`、`agent-vault`
- **tp-side**：`identity-service`、`review-service`、`phc-service`、`did-service`、`supervision-service`
- **ap-side**：`agent-service`、`subagent-service`、`lifecycle-service`
- **cross-domain**：`gateway`、`policy-service`、`audit-service`、`coordination`

`services/` is grouped by party: `user_side/`, `tp_side/`, `ap_side/`, `cross_domain/`, and `ipfs/`.

- `services/shared/` contains common DTOs, error handling, configuration, HTTP helpers, and service adapters.
- `services/user_side/`, `services/tp_side/`, and `services/ap_side/` contain each party's services.
- `services/cross_domain/` contains the cross-party gateway, coordination, policy, and audit services.
- `services/ipfs/storage_service/` is the fifth-party encrypted-object service and intentionally has no cryptographic client.

`tests/unit/test_backend_skeleton.py` 6 项钉死：目录与分层齐全、crypto_client 仅经 sdk、15 个 app 可 import、FastAPI 缺省时 build_app 安全降级。

## 已完成：`apps/` 四方前端（第 8 步）

四个前端**各自独立部署、各自独立域名**（§10），外加一个中立的 `shared/`：

| 应用 | 区 | 只允许访问 | 页面 |
| --- | --- | --- | --- |
| `user-web` | User | `/api/user` → `portal-api` | auth、phc、agent、subagent、**subagent/confirm**、vault、lifecycle |
| `tp-web` | TP | `/api/tp` → identity / review / phc / did / supervision | review、phc、did、supervision |
| `ap-web` | AP | `/api/ap` → agent / subagent / lifecycle | modules、primary-agents、sub-agents、lifecycle |
| `ops-web` | 跨域治理 | `/api/ops` → gateway / policy / audit / coordination | overview、module-review、stats、permissions |

`shared/` 只放**不含区属性**的代码：`ui/`（外壳与主题）、`auth/`（会话抽象，四套权限模型互不通）、
`api-client/`（序列化与错误归一）、`types/`（与 `packages/contracts/` 对齐的最小公约数类型）。
判断标准很简单：**一旦某段代码需要知道自己在哪个区，它就不属于 shared。**

### 前端边界卡口：把 §10 网络策略变成 CI 规则

`scripts/check_frontend_boundary.py` 是 `crypto/guard` 的前端对应物，`node_modules/dist` 自动跳过：

| 规则 | 拦什么 | 为什么 |
| --- | --- | --- |
| **F1** | 引入加密库（`crypto-js` / `node:crypto` 等）、调用 SubtleCrypto、出现密钥材料标识符 | 加解密只在后端 `crypto.sdk` 内发生，浏览器侧不得碰密钥 |
| **F2** | 某区前端出现其他区的 `/api/xxx` 前缀 | 跨域只能经后端 `coordination`，前端不得直连 |
| **F3** | 把会话/凭据写进 `localStorage` | 会话只进 `sessionStorage`，关闭标签页即失效 |
| **F4** | `shared/` 里出现 `BASE_URL` 或任何区前缀 | 区划属属于各 App，不得下沉到共享层 |
| **F5** | 缺少 `src/services/api-client.ts`，或 BASE_URL 与所属区不符 | 每个 App 必须有唯一的后端出口 |

`api-client.ts` 里还有一层**运行时**兜底：`assertSameZone()` 对非本区路径直接抛错，
即使有人绕过了 CI，浏览器里也走不通。

### workspace 布局（别在单个 App 里 npm install）

`apps/` 是 npm workspaces 根，依赖**提升到 `apps/node_modules`**。原因不是洁癖：
`shared/` 与四个 App 是同级目录，若依赖装在 `user-web/node_modules`，`shared/ui` 向上解析时找不到
`react` 的类型声明，直接报 `TS2307`。提升后四个 App 与 shared 共用同一份解析。

```bash
cd apps && npm install        # 在根装，不要进单个 App
npm --workspace @tpaa/user-web run build
```

`App.tsx` 因此用相对路径 `'../../shared/ui'` 引用共享层——刻意不用 `@shared/*` 别名，
别名要在 vite config 里 `path.resolve`，那会引入 `@types/node` 依赖；相对路径零配置且零依赖。

### 实跑验证（不是"应该能编译"）

`user-web` 已真实通过：

- `npx tsc --noEmit` → 退出码 0，无类型错误
- `npx vite build` → 41 个模块转换成功，产出 `dist/index.html` + `dist/assets/index-*.js`（163 kB / gzip 54 kB），耗时 1.92s

`node_modules/` 与 `dist/` 自动被两个 CI 卡口跳过，装完依赖后 `check_frontend_boundary`、`crypto.guard` 仍为 0 违规。

`tests/unit/test_frontend_skeleton.py` 13 项钉死：四个应用与 19 个页面落地、每个 App 的 BASE_URL 落在本区、
派生确认页存在（V4 硬要求）、当前 `apps/` **零违规**，以及 F1–F5 每条规则**真能抓到**违例样本、
注释里的说明文字不误报。

## 已完成：陷门收口 · HSM 注入式（第 9 步，红线 1 的最终形态）

第 5 步把密钥关进了 HSM，**引擎却还在收 `tp_sk` / `ap_sk` 这类原始标量** ——
等于工程扩大了保险柜，却把钥匙摊在办公桌上。第 9 步把这处残留彻底拆掉。

### 改了什么

| 之前 | 现在 | 为什么 |
| --- | --- | --- |
| `issue_phc(tp_sk=..., tp_ch=...)` | `issue_phc(tp_hsm=..., ap_ch=ap.public_chameleon())` | 私钥/陷门不进调用栈，签名在句柄内完成 |
| `update_by_ap(ap_sk=..., ap_ch=...)` | `update_by_ap(ap_hsm=...)` | 求碰撞走 `ap_hsm.chameleon_collide()`，陷门不进函数作用域 |
| `seal_child_did(tp_sk=...)` | `seal_child_did(tp_hsm=...)` | 派生里唯一要签名的动作，同样只注入句柄 |
| 跨域互传 `ChameleonHash` | 跨域只传 `PublicChameleon` | 前者把改写权一起交了出去，算法1 的"AP 独自完成"会名存实亡 |

`crypto/primitives/chameleon.py` 因此多出一个类型：

```
PublicChameleon   只有 cpk —— compute / rand 能用，forge 抛 TrapdoorUnavailable
ChameleonHash     持有陷门 —— 上面那些都能，外加 forge（仅它自己与 hsm/soft.py 可以碰）
```

### 四道防线，缺一味都不算收口

1. **类型层**：`PublicChameleon.forge` 直接拒绝 —— 跨域那份句柄就算被拿到也改不了内容。
2. **注入层**：两个引擎只收 `*_hsm`，出现任何 `*_sk` 立刻 `TypeError` 并点名红线 1
   （`reject_raw_keys`，PHC 与派生**共用一处定义**；顺手连拼错的参数名也不放过）。
3. **降级层**：只读动作（`verify_phc` / `derive_child_phc` / `verify_lineage`）进来先把句柄
   `as_public()` 降级 —— 这个作用域里压根不存在陷门，自然没有"顺手用一下"的可能。
4. **静态层**：guard **R4** 把 `.forge(` 钉死在两个文件里，**连 crypto/ 内部其他文件**都没有资格碰，
   `demos/` 也一样不豁免（演示脚本会被抄走当样板，更不能示范绕过）。

签发这一步额外有一道 **`require_public`**：写进凭证的跨域句柄若带着陷门，当场 `PermissionError`。
这里刻意**不做静默降级** —— 悄悄把陷门抹掉，调用方会以为自己传对了，而那条被绕过的红线再没人看得见。

### 测试怎么钉的（14 项，前缀 `test_step9_` 与 R4 用例）

- 传 `tp_sk` → `TypeError` 且错误信息点明红线 1
- 拼错 kwarg → `TypeError`（收口守卫不能吞笔误）
- `PublicChameleon.forge(...)` → `TrapdoorUnavailable`
- 把**含陷门**的句柄塞给签发 → `PermissionError`
- 拿 AP 的句柄去做 TP 的动作 → `PermissionError`（双域隔离）
- 派生阶段不产生任何签名 → 证明没有任何私钥被调用
- R4：业务层、`crypto/phc/engine.py`、`demos/` 里出现 `.forge(` 全部被拦；两个白名单文件放行；注释里提到 forge 不误报

最后的端到端复核 `test_step9_ap_rewrite_needs_only_ap_hsm`：TP 只留下公钥就"离线"，
AP 独自完成更新，校验照样通过 —— 算法1 的那句话现在有代码替它作证。

**调用方式变了，旧的 `tp_sk=` 写法连报错都会提醒你改成 `tp_hsm=`。**

## 已完成：`agent-service` 业务落地（第 10 步，端到端跑通）

前九步完成密码学地基与按责任方分组的服务骨架；这一步选择 AP 智能体服务，跑通
再按后续任务补齐端口实现、启动自检、集成测试与巡检脚本。

### 链路（一条请求走完 D1–D6）

```
POST /v1/agents/issue
  D2 查重 ── 同一 H(ID) + 同一 selection 且仍 active → 直接返回既有实例（keptExisting=true）
  D3 解析模块 ── 存在？未下架？manifest 摘要对得上？
  D4 算 CMI ── selection 归一化 → 哈希链逐层值 + 终值
  TP 签发 ── issue_phc(parent_did=...)   ← AF 在这里被算定
  D6 封 DID ── seal_did()  唯一 DID + ECID（CID 的加密形态）
  D4' 算法1 ── write_cmi()  AP 用自己的陷门把 CMI 写进 APM，APCH 取值不变
  D5 三方一致 ── PHC 验签 + APM.CMI == cmi.json == 本地重算
  落盘 ── meta / selection / cmi / phc / versions / build/<v>/
  索引 ── by-identity.enc（加密）+ by-owner-did.json
```

**为什么「先封 DID、后算法1」是安全的**：算法1 改的是 APM，APCH 取值不变，它不依赖 TPM 里有没有 DID。
两步谁先谁后，验签结果相同。选后做的理由只有一条 —— 让日志里呈现
「TP 的所有动作在前、AP 的动作在后」；一旦发现 AP 的动作跑到了 D6 前面，说明有人绕过了封印。

### 四道校验（缺一项，异常就会被"看起来正常"吞掉）

| 位置 | 判据 | 失败处置 |
| --- | --- | --- |
| D5 验签 | TP 签名 / AF 锚定 / APCH / TPCH | `IssueRejected` → 400，不落盘 |
| 算法1 后 | APCH / TPCH / AF **三项必须不变** | `CapabilityError`，拒绝落盘 |
| 落盘后 | `buildDigest` 确定性可重现 | 见下「确定性重建」 |
| 读取时 | 重算 CMI == cmi.json == PHC.APM.CMI | 冻结 + 告警，**不自动修复** |

第三行的要点：`build` 是 `selection + modules` 的纯函数产物，同输入必须同 digest。
做不到确定性，"找回"就只是"大概能跑"，那不是承诺。

### 状态机（实例级）

```
              issue / derive
                    │
                    ▼
               ┌─────────┐   校验失败 / 模块仓库受损 / 上级吊销
               │ ACTIVE  │ ────────────────────────────────▶ ┌────────┐
               └─────────┘                                    │ FROZEN │
                    │  TTL 到期（sweep，仅子体）                └────────┘
                    ├───────────────────────────────────────────▲
                    │  用户注销 / 追溯吊销                        │ 保留取证，永不删除
                    ▼
               ┌─────────┐
               │ REVOKED │ ── recycle/（软删，保留恢复窗口）
               └─────────┘
```

`FROZEN` 是本步骤里最重要的一个状态：它**只减权限、不删数据**。
冻结之后 `recover` 直接拒（409），runtime 不能拉起，但文件全都还在 ——
事后追溯时，"这一环当时被冻了、因为什么"本身就是证据链的一部分。

### 算法1 为什么不在 `TP` 那一侧

`CapabilityPort` 里有四个动作：`issue_phc` / `seal_did` / `write_cmi` / `verify_phc`。
前三个看起来像"找 TP 做事"，只有 `write_cmi` 不是 —— 它必须由 AP 自己做，
因为 APCH 的陷门只存在于 AP 的 HSM 里，TP 手里只有公钥（算得出值，改不了内容）。

代码上的安排是让这件事**成为类型事实**而不是注释：适配器同时持有
「对方」（`LocalTpAuthority`）与「自己」（AP 的 HSM），而 `write_cmi` 的实现体里
**根本没有 TP 可调用**。想让它去问 TP，得先改构造函数签名 —— 那一步会在 review 里被看见。

### User executor HTTP adapter (A轮)

`services.user_side.executor_service` 是隔离测试适配器，默认 `profile=test-adapter`，只允许绑定 loopback。它从 `TPAA_EXECUTOR_STATE_ROOT` 读取测试状态，并由 `TPAA_EXECUTOR_TOKEN` 保护；状态目录中的 `keys.json` 是明文测试密钥，只能用于开发/验收，不能代表用户独立控制或生产密钥托管。

单个 executor 进程只服务一个 `TPAA_EXECUTOR_OWNER`。多用户必须使用多个进程和端口。loopback + 共享 token 只防远程冒充，不防同机恶意进程；本轮不具备 TEE、硬件钱包或用户确认 UI 的安全含义。

Portal 的生产装配不再持有 TP/AP 认证 issuer seed：它向目标域 `/v1/auth/challenge` 取挑战，经 executor `/v1/executor/login-body` 签名，再向同一域 `/v1/auth/login` 换短期 token。TP/AP/Portal 使用进程内一次性 challenge 时必须单 worker；不要把 `JsonStore.update()` 当作跨进程原子消费。

示例启动：

```powershell
$env:TPAA_EXECUTOR_BIND = "127.0.0.1"
$env:TPAA_EXECUTOR_STATE_ROOT = "D:\data\tpaa\executor-user"
$env:TPAA_EXECUTOR_TOKEN = "replace-with-a-local-secret"
python -m uvicorn services.user_side.executor_service.app:app --host 127.0.0.1 --port 8110 --workers 1
```

A 轮真实 socket smoke 只覆盖 executor 独立进程和 B1 challenge/login；phc-service 当前不能独立部署，因此 G3/D6 仍由同进程 TP 装配覆盖。

```bash
# 启动自检：装配时就跑，任何一项不过就拒绝启动（不带病启动）
TPAA_STORE_ROOT=... TPAA_INDEX_KEY=... TPAA_ECID_KEY=... TPAA_HSM_SEED=seed.json \
  python -m uvicorn "services.ap_side.agent_service.app:app"

# localstore 巡检：独立于测试，可以直接在生产库上跑；默认只报告、不动手
python scripts/verify_localstore.py --root ./localstore --hsms seed.json
python scripts/verify_localstore.py --root ./localstore --hsms seed.json --freeze   # 发现问题即冻结
python scripts/verify_localstore.py --root ./localstore --json                     # 喂监控
```

巡检四类判据与上表一致，但**不依赖业务代码路径**：`buildDigest` 是从磁盘重算的，
不是读 `integrity.json` 里的某个字段 —— 拿被检查对象自己的记录当判据，那是自证。

`--freeze` 默认关闭是有意的：一个"查的时候顺手改状态"的工具，出事时没人敢用，
因为分不清看到的是现场还是它自己造成的。

### 这一轮修掉的真实缺口（都是测试逼出来的）

1. **PHC 里 `APM.CMI` 一直是空的**。签发、封印都做完，看着一切正常，但凭证上承诺的配置是空值。
   补上 `WriteCmiRequest` + `write_cmi` 之后才真正走完算法1。
2. **`AF` 锚定的 `parent_did` 来得太晚**。`AF = CH_TP(H(ID)‖τ‖CRF‖APCH‖parent_did)`
   在签发时就已算定；原先 `parent_did` 是等 `seal_did` 才写进 PHC 的，
   于是 AF 里锚的是空串、TPCH 里写的是真父体，**永远对不上**。
   这个坑最阴的地方：**主体永远碰不到**（主体 parent_did 恒为空），只有派生时才暴露，
   而报错是「AF 锚定不一致（身份因子或监管因子被动过）」，指向的是身份被改，跟顺序错了毫无相似之处。
   修正：`issue_phc(parent_did=...)`，让 TP 在同一次签发里锚定，单一来源。
3. **`meta.json` 落了 H(ID) 明文**。`localstore/index.py` 的文件头从一开始就写着
   "为什么不把 H(ID) 放进 meta.json"，但实现还是抄了进去 —— 于是"身份映射全库只有一处"
   这句话在数据层面不成立。修正：meta 不再存 H(ID)；派生时需要的 H(ID) 改由
   `identity_index.find_by_did()` 反查（H(ID) 始终来自服务端自己登记过的事实，
   而不是调用方传参 —— 否则"用户手动确认"就成了"替别人点头"）。
4. **模块仓库受损只报 400、不冻结**。原先是"这次请求失败"，实例仍是 `active` ——
   用户再点一次重建、或者 runtime 直接拉起，就会拿着被换过的代码跑起来。
   平台明明已经知道它坏了，却让它继续活着。修正：仓库完整性受损与 CMI 不一致**同级处置**
   （冻结 + 409），但告警消息区分两者（`detail` 字段），因为排查方向完全不同。
5. **`crypto.sdk.verify_phc` 传 dict 直接崩**。引擎只接受 PHC 对象，
   而业务侧手里拿的一律是 JSON。崩出来的是
   `'dict' object has no attribute 'apch_message'` —— 看起来像验签逻辑坏了，实际只是没转。
   修正：sdk 这一层同时接住对象与 dict（sdk 是给业务用的，就该接业务手里的形态）。

### 测试

```bash
python run_tests.py --all       # 本步 131 项；第 11 步补到 164 项（单元 + 对抗 + 集成）
```

集成测试（27 项，真起 HTTP、真落盘）覆盖：健康检查、`create_app()` 无参必须失败、
申领落盘全字段、第三方可验、查重、一人多体、下架/不存在模块拒绝、坏 hash 422、
**无令牌派生 403 且零副作用**、prepare 不落盘、派生 happy path、
令牌一次性、令牌绑定方案、confirm digest 不符、子体不可再派生、
locate 只列不改、找回重建（buildDigest 一致）、他人 DID 拒绝、模块篡改冻结、
冻结不可交付、sweep 只冻子体不删、**localstore 无 H(ID) 明文 / 无 CID 明文**、索引非明文。

`run_tests.py` 的跳过机制也顺手改了：原来看函数名里有没有 "skip" 来判断，
一个真实的断言失败如果恰好叫 `test_skip_xxx` 就会被记成 SKIP —— 把失败伪装成跳过。
改成显式抛 `Skipped` 异常。

## 已完成：追溯链贯通（第 11 步，六个服务）

第 10 步只跑通了「申领」。这一轮把**另一半**补上：出了事，平台怎么找到人、怎么证明、怎么停掉。
六个服务同时落地，横跨三个责任方：

```
                    ┌──────────────── TP 侧 ────────────────┐
  举报 ──▶ supervision-service ──▶ did-service（号码簿 / CSCID 封存）
              │        ▲                    ▲
              │        │ AF 复核            │ 级联撤销
              ▼        │                    │
        coordination ──┴──▶ lifecycle-service（AP 承接、停运）──▶ agent-service
              │                                  ▲
              ▼                                  │ 通知
        audit-service ────────────── policy-service（吊销令）
                    └──────────── 跨域 ──────────┘
```

### 一句话概括每个服务管什么

| 服务 | 方 | 只做一件事 | 它**不**做什么 |
| --- | --- | --- | --- |
| `did-service` | TP | 记「这个 DID 属于谁（密文）」+「上一环是谁」 | 不认识"立案"这件事；拿到了 CSCID 也打不开 |
| `supervision-service` | TP | 管案件状态，未立案一律拒 | 不存密钥之外的身份信息；不直接停 AP 的实例 |
| `coordination` | 跨域 | TP↔AP 唯一通道 + 限流 + 载荷卡口 | 不转发任何非标量；不允许发起方自答 |
| `policy-service` | 跨域 | 按令吊销、级联、广播 | 不自己算归属；无案由的令直接拒 |
| `audit-service` | 跨域 | 哈希链账本 + 取证导出 | 只有 append，没有 update/delete |
| `lifecycle-service` | AP | 承接吊销、停运本地实例、应答协查 | **手里没有任何密钥** |

### 追溯的两条路径（互为校验）

```
路径 A（凭密文还原身份）  子 DID ──▶ 注册表取 CSCID ──▶ 监管私钥解密 ──▶ H(ID)
路径 B（凭凭证找上一环）  子 DID ──▶ PHC.AF ──▶ 解出 parent_did ──▶ 逐级上溯到根
```

只保留 A，注册表被改一行就查错了人；只保留 B，凭证被换一份就找不到根。
两条都走，再拿 A 得到的 H(ID) **复算 AF**（`AF = CH_TP(H(ID)‖τ‖CRF‖APCH‖parent_did)`）：
复算对得上，说明"这个身份确实是这份凭证承诺的那个"；对不上，说明 CSCID 或凭证被调换过。
`test_disclosure_detects_swapped_cscid` 就是往注册表里塞一份别人的密文，看揭露会不会自己发现。

### 闸门：未立案一律拒，而且是 403

`Case.guard(*allowed)` 是这条规则**唯一的实现处** —— 协查、揭露、取证三处都要经过它。
不允许各用例自己写 `if case.state != FILED`，因为那种写法迟早会有一处漏掉。

状态机是显式表，不接受"顺手迁移"：

```
reported ──┬─▶ filed ──▶ investigating ──▶ disclosed ──▶ sealed ──▶ revoked ──▶ closed
           └─▶ rejected（终态，不可逆）
```

HTTP 上的分工同样是刻意的：**403 是"你在越权"，400 是"你填错了"**。
合并成 400，安全日志里就再也分不出"有人试图在没立案的情况下还原身份"。

### 立案：两个人，两次签字

`file(reviewers)` 要求去重后至少两人。`["a", " a "]` 这种也算一个人（先 strip 再比）。
理由很直白：立案这个动作**会打开还原身份的能力**，一个人点两下就能开，等于没有复核。

### 吊销：三段式，每段失败都不一样

```
第 1 段 撤销（did-service，按 parent_did BFS 展开全后代）
        失败 → 令记 failed，**不通知 AP**
        理由：凭证还有效就把实例停了，会出现"有效凭证跑不动"的怪状态
第 2 段 通知（lifecycle，停运本地实例）
        失败 → 令停在 cascaded，等 ResendNotice 补齐
        理由：吊销已经生效，AP 晚一点停是可接受的降级
第 3 段 留痕（audit）
        失败 → 抛。没留痕的吊销等于没发生过
```

子体的 `revoke_source` 记 `cascade` 而不是 `direct` —— 出事后要能回答"这个是他自己犯事，还是被上层带下来的"。

`lifecycle` 还有一处防守：**它不信广播的完整性**。广播只点名了主 DID，本机若还存着子体，
照样按 `parent_did` 再扫一遍。`test_lifecycle_sweeps_local_descendants_even_if_broadcast_misses_them`
就是模拟"上游漏了一个"。

### 审计链：只有 append，连"改"这个入口都没有

```
hash_i = H(hash_{i-1} ‖ seq ‖ entry_id ‖ at ‖ kind ‖ subject ‖ canonical(payload))
```

`seq` 与 `entry_id` 参与计算，是为了让**插入**也能被发现 —— 只算内容的话，
把第 2 条复制一份插到第 3 位，链依然自洽。

`verify_entries()` 返回 `ChainVerdict(ok, length, broken_at, reason)`，断点可定位到具体第几条。
取证包导出时**现场重算一遍**，而不是读某个布尔标志：取证发生在立案之后、导出之前，中间可能有人动过账本。

导出包里有：记录、核验结论、整包摘要（`bundleDigest`）。
导出包里**没有**：密钥、H(ID) 明文、CSCID、CID。
`test_audit_export_bundle_is_self_contained_but_harmless` 直接对响应文本做字符串检查。

### 这一轮修掉的真实缺口

1. **`LocalAudit` 没有 `verify()`，取证包的"链已核验"恒为 False**。
   取证用例写的是 `getattr(self.ctx.audit, "verify", None)` —— `hasattr` 为假时静默降级成 `None`，
   于是 `chain_verified` 永远是 `False`。**这类"可选能力"最危险**：不是报错，是安静地给出错误结论。
   修正：给 `LocalAudit` 补 `verify()`，转调 audit-service 的 `VerifyChainUseCase`。
2. **`audit-service` 缺 `ValueError` 处理器，"导出不写案由"变成 500**。
   操作者看到 500 会去翻服务日志，而真正的问题是请求本身不成立。
   修正：补 `ValueError → 400`。5xx 必须只意味着"我们出问题了"。
3. **`policy` 的 `LocalNotify` 从 `domain.usecases` 取 `RevocationNotice`**，
   而那个类住在 `domain.entities`。表现是吊销全部生效、`notified == []`、令停在 `cascaded` ——
   看起来像"AP 没响应"，实际是导入路径写错。这类错误只有跑全链才暴露。
4. **`/v1/dids/{did:path}` 会吞掉 `/trace`**。DID 里带冒号、路径里带斜杠，
   路由顺序错一行，`GET /v1/dids/xxx/trace` 就被解析成 `did="xxx/trace"`，报 404 ——
   看起来像"这个 DID 没登记"。修正：`/trace`、`/children`、`/cscid` 三个路由排在 `{did:path}` 之前，
   并留 `test_did_subroutes_are_not_swallowed_by_path_param` 钉住。
5. **`SupervisionKey` 序列化降级后 `public()` 直接崩**（`None.n`）。
   修 `public()` 从 `_degraded_n` 取值，并让 `open()` 抛 `PermissionError` 而不是 `AttributeError` ——
   "这把钥匙现在打不开了"必须是一句能读懂的话，否则运维会以为是代码 bug。

### 测试

```bash
python run_tests.py --all       # 164 项：单元 + 对抗 + 集成
python demos/personal_agent/demo_trace.py   # 全链演示（含每一次被拒绝的打印）
```

| 层 | 文件 | 项数 | 证明什么 |
| --- | --- | --- | --- |
| 领域层 | `tests/unit/test_trace_chain.py` | 16 | 规则：未立案不许查、双人复核、驳回不可逆、级联不漏人、审计可定位、CSCID 被换能查出来 |
| HTTP 层 | `tests/integration/test_trace_api.py` | 17 | 接缝：`{did:path}` 不吞子路由、403/409/422/429 各归其位、导出包无秘密、限流生效 |
| 原有 | 其余 | 131 | 密码层 / 派生 / IPFS / localstore / 申领链路 |

全链装配只有一份，放在 `tests/harness.TraceChain`，两层测试共用 ——
两套夹具各写一遍的话，早晚有一边悄悄少接一个服务，而那种"少接"表现出来是"某个功能忽然不生效"。

### 真实缺口（还没做，写在这里而不是藏起来）

1. **协查应答没有 HTTP 端点**。AP 侧的计算在 `lifecycle-service` 的用例里，
   但"把答复发回 TP"目前靠直接调 `coordination` 的用例。真实部署要有 AP 的 gateway 提供
   `POST /v1/assist` 并由它转投工单 —— 这条边界现在没画。
2. **只有主智能体能派生一层**，所以级联测试里的"孙体"是直接往注册表登记的。
   注册表这一层不该有同样的限制（否则将来放开多级时，级联会悄悄只走一层）。
3. **吊销完成后，案件状态停在 `sealed`**。`policy` 没有回头告诉 `supervision` "这案子已经执行完毕"，
   `CaseState.REVOKED` 目前只能手工迁移。
4. **服务之间仍是进程内适配器**。`LocalDirectory` / `LocalChannel` / `LocalNotify` 换一次函数调用
   就代表一次跨域调用；切分区部署时把适配器换成 HTTP 客户端即可，domain 一行不用改 ——
   但这句"即可"没被验证过，因为没有 mTLS 与网络策略。
5. **审计账本是单机 JSON 文件**，没有 WORM 存储、没有外部时间戳锚定。
   "链自洽"能证明"没被偷偷改过而不留痕"，不能证明"对方没把整份账本换掉"。
6. **监管 Paillier 密钥在软件里**（`crypto/hsm/supervision.py` 已按红线 1 做成句柄形态，
   序列化即降级），生产必须落到 HSM/KMS。

## 脚手架工具

`scripts/gen_services_skeleton.py` / `scripts/gen_frontend_skeleton.py` 只创建目录与占位文件，
**不 import 任何密码学内部**（对 `crypto.guard` 安全）。可重复运行；已存在的文件默认不覆盖，`--force` 覆盖重建。

## 已修复的真实 bug（留档）

1. **ladder 累加器接反**：先 `cswap` 再 `cselect`，两者叠加导致 bit=1 时把 `2·R0` 当成了结果。
   表现是 `point_mul(1) != G`、验签恒失败。修正：只用 `cselect`，去掉冗余 `cswap`。
2. **Paillier 模逆用错方法**：`pow(a, n-2, n)`（费马小定理）只对素数模成立，而 Paillier 的 n 是合数。
   必须用 `pow(a, -1, n)`。
3. **`apa_apid` 设置时机错**：`issue_phc` 里 AP 公钥必须在算 APCH **之前**设好，否则消息不一致 → APCH 恒校验失败。
4. **IPFS 包名用了连字符**：目录原名 `backend/ipfs-side/`，Python 包名不能含连字符，导致 `ModuleNotFoundError`。
   修正：目录重命名为 `services/ipfs/storage_service/`。
5. **根目录散落示例脚本触发 CI 卡口**：`demo_derive.py` 原在项目根，被 guard 按红线 2 判为越权。
   修正：归入 `demos/`（豁免目录），`sys.path` 指向项目根。
6. **信封往返测试误用密钥**：`seal_secinfo` 返回的第一个值是**派生后的实际密钥**，unseal 必须用同一个；
   原测试误传原始 seed key。修正测试用返回值。
7. **生成器把 crypto_client 覆盖成空占位**：`crypto_client` 既单独用模板写入，又被通用 `LAYER_DIRS` 循环用空占位覆盖。
   修正：从 `LAYER_DIRS` 移除 `crypto_client`。
8. **前端卡口把根路径写死了**：`_check_app` 里用 `p.relative_to(ROOT)` 算相对路径，当扫描目标不是项目根
   （如测试用的临时目录）就抛 `ValueError`，导致 7 项检测用例全部崩掉而非正常断言。
   修正：新增 `_rel(p, root)` 助手，相对**传入的根**计算，不在其子路径时退回绝对路径。
9. **monorepo 依赖没提升，shared 拿不到 react 类型**：最初 `@shared/*` 别名 + 依赖装在单个 App 里，   `tsc` 报 `TS2307: Cannot find module 'react'`（shared 在 App 目录之外，向上找不到 node_modules）。
   修正：frontend 改为 workspaces 根，依赖提升到 `apps/node_modules`；App 改用相对路径 `../../shared/ui`
   （不引 `@shared/*` 别名，避免为 `path.resolve` 引入 `@types/node`）。
10. **PHC 序列化漏了三个随机数**：`to_jsonld()` 少了 `tpm_af_r` / `proof_tpch_r` / `proof_apch_r`，
    导致「写出去 → 读回来 → 验签」必然报 AF 不一致。漏随机数比漏普通字段更隐蔽：
    值本身是对的，只是缺了它就算不出同一个承诺。
11. **`AF` 锚定的 `parent_did` 来得太晚**（详见步骤 10 第 2 条）：主体永远碰不到，
    只有派生时暴露，报错还指向"身份被改"。
12. **`crypto.sdk` 漏导出 `ser_point` / `deser_point`**：`sdk/keys.__all__` 里有，
    `sdk/__init__` 没导出，业务侧按文档写就 `ImportError`。

## 对抗测试覆盖

`tests/adversarial/` 11 项 + `tests/unit/test_phc.py` 内 12 项对抗用例（含第 9 步的收口用例），每条都是"攻击必须失败"：

- 伪造签名（冒充 TP 背书）→ 验签失败
- 签名延展（改 s / 改 R）→ 验签失败
- **nonce 复用 → 私钥被复原**（反面用例，证明为什么 k 必须独立取样）
- 无陷门求变色龙碰撞 → 失败（对照：有陷门则成功）
- 篡改模块代码 → CMI 不一致
- 仅调换模块顺序 → CMI 不一致
- TP 单方解密盲化后的监管因子 → 拿不到真实身份哈希（对照：AP 提供 ρ 后可还原）
  ⚠️ 这条只在测试内的 `_blind_wrap` 上成立，**业务揭露路径没有用它**，见下「已知问题」
- 用旧 CMI 冒充当前版本 → 检出
- 传原始私钥标量给引擎 → `TypeError` 并点名红线 1
- 在公开句柄上求碰撞 → `TrapdoorUnavailable`
- 把含陷门的句柄塞给签发 → `PermissionError`（否则 TP 就握住了 AP 的改写权）
- 拿 AP 的句柄去做 TP 的动作 → `PermissionError`

## tpaa_v1：当前主协议（本地 test-adapter）

按《TPAA说明书》+ [勘误](docs/protocol-errata/tpaa_v1.md) 重建的协议层，与 proto0（`crypto/phc`）并存。
公式到代码的对照见 [docs/protocol-map/tpaa_v1.md](docs/protocol-map/tpaa_v1.md)。
已有：参数（RFC 3526 3072 bit）、规范化编码、每凭证 CCH 陷门、PHC v1 签发 / 算法1 / 算法2 / 校验、HCGen、
IRF/RF、ECID 两段式；协议层 G1→G4→D1–D6→R1→R2 全链（CR / 审批证据 / TPAC / AR / CMM / PACI / PAR / DIDGR /
CSCID / did:wba / CDID / SecInfo），用户、TP、AP 三方各一个文件。
服务：`identity-service`（受理 CR、掩码审核视图）、`review-service`（**一名**审核员判定、审批证据）、
`phc-service`（签发 / D6）、`agent-service/v1_app.py`（D2 / D4 / 发布 / 本地 Runtime），
以及服务端持钥的用户执行器。Portal 已按用户主动操作编排 G1→FINAL；代码入口已包含 PUB/RUN，
当前 User Web 主流程是否开放以 `RUNNING.md` 为准。
端到端见 `tests/integration/test_tpaa_v1_http.py`。
追溯（R1 / R2）：`supervision-service/v1_app.py`（举报 → 两名监管员个人签字立案 → 跨域协查 → 揭露 → 取证包），
AP 侧 `POST /v1/tpaa/assist` 用**自己的**监管员名录核对签字后才交回 s_ap（errata E18）。proto0 的追溯链保持不变。
v1 仍未完整接入：说明书 3.1–3.3 的 RE / U / T、跨进程吊销状态发布、用户独立控钥、
现实身份核验机构和独立 TP/AP 生产部署。新加的 P0–P2 边界见
[P0–P2 实施口径](docs/protocol-map/p0-p2.md)：正式 identity-service 要求可信核验方签名的
身份核验证据；本地演练需显式 `test_adapter=True`。证据接口本身不执行证件或生物识别核验。

AG2 设计与本地沙盒：`packages/tpaa_runtime/manifest.py`（PHC / DID / CMI / BuildDigest / 能力 / 工具模板）、
`packages/tpaa_runtime/sandbox.py`（Tool Gateway、用户确认、审计、确定性本地对话），演示：

```powershell
& $py demos/personal_agent/demo_ag2_sandbox.py
```

本沙盒不接 LLM 和真实外部 API，先验证"Manifest → 能力 / 工具 → Tool Gateway → 用户确认 → 审计"。
真实 API 只能通过 connector + `secretRef` 接入，API Key 不得进入 PHC、CMI、Manifest、对话或审计日志。
当前已有本地 AG2 test-adapter 启动路径，但它使用固定测试配置与演示工具；
真实对话模型、真实工具连接器及 U/RE/T 尚未形成正式部署链。
审核员 / 运营人员用各自的 STAFF 密钥登录（角色取自人员名录）。令牌由各域 AUTH 签发方签名，
`aud` 分 `tpaa:tp` / `tpaa:ap`，跨域无效；有效期 30 分钟。审核员身份取自令牌，请求体里没有 reviewer 字段。
仍需 TLS；人员名录"一人一把钥匙"是组织规矩，代码管不到。
TP 三个服务之间是进程内端口，只能同进程装配；独立部署要先把端口换成 HTTP 客户端。

## 已知问题：区分 proto0 与 tpaa_v1

| # | 问题 | 状态 |
| --- | --- | --- |
| K1 | **AP 变色龙陷门可被 TP 还原**：算法1 后同一 APCH 有两组公开开口，`x = (m1−m2)/(r2−r1)`。TP 持有签发版与最终版 PHC 即可解出。当前挡住伪造 CMI 的只剩 APproof 签名，"APCH 只有 AP 能改"不成立 | proto0 未修复（`test_trapdoor_exposure.py` 钉住现状）；**tpaa_v1 已消除**（随机数不进 PHC） |
| K2 | proto0 的揭露只用监管私钥；v1 正常协查流程要求 AP 返回 `s_ap`，但 TP 的记录仍可把 DID 关联至 `H(ID)`，且 R2 恢复函数本身不以 AP 授权为密码学前提 | proto0 未修复；v1 有流程双控，**没有密码学双控**，见 S2 |
| K3 | `crypto/phc/schema.py::_h` 拼接无分隔/长度前缀/域分离，存在编码歧义 | proto0 保持原样；**tpaa_v1 已改用规范化编码** |
| S1 | **说明书原文**：CCH 的陷门就是 sk_tp / sk_ap，用户由 (r_bind, r_bind') 可解出 TP/AP 主私钥 | tpaa_v1 改为每凭证一对陷门（errata E1）；用户仍能解出**本凭证**的陷门，见 errata 限界 |
| S2 | TP 存有 H(ID)→r_bind，可单方把 DID 关联到身份 | 原文结构所致，v1 未消除，写为限界 |
| K4 | proto0 的部分 API 与派生确认缺少完整认证；v1 的用户/审核员路由已有域令牌，Portal 本地会话仍只是 test-adapter | proto0 待治理；v1 不得称为生产身份认证 |
| K5 | proto0 曾一次请求完成 G3→D6；v1 已拆出 G1/G4/D5 用户侧校验及人工审核，Portal 编排这些阶段 | v1 的**流程缺口已修**；用户独立控钥和真实身份核验仍未完成 |

已修复（`tests/unit/test_p0_fixes.py`）：DID 发号落盘、生产装配必须注入 HSM 种子（`TPAA_HSM_SEED`）、
TP 替身只收 AP 公钥材料、派生确认必须 prepare 过 / 只能确认一次 / 令牌绑定父体 / 并发只核销一次。

## 红线（写进代码注释，也在 CI 检查）

1. 本层是**唯一**允许接触密钥材料的地方
2. 上层不得自行实现加密，只能调 `crypto/sdk`（经 `crypto.guard` 强制）
3. LLM 不参与任何密码学运算
4. IPFS 方**绝不持有任何密钥**，只存密文（红线 16）
5. CID 在链上**以 ECID 形态存在**，不得明文落盘（红线 17）
6. IPFS 方**每次取用必须留痕**，独立于 TP 日志（红线 18）
7. 私钥**只存在于 HSM 实例内**，序列化 / 传输不得携带（红线 1 的可强制实现）
8. TP 与 AP 的 HSM **双域隔离**，互不持有对方陷门
9. 上层越权调用密码学由 `crypto/guard` 静态卡口拦截（CI 失败）（红线 2 的可强制实现）
10. 前端**不做加解密、不持有任何密钥材料**（`check_frontend_boundary.py` F1 强制）
11. 前端**只访问本区后端**，跨域一律经 `coordination`（F2 静态 + `assertSameZone()` 运行时双重强制）
12. `shared/` **保持区中立**：不得出现 BASE_URL 或任何 `/api` 前缀（F4 强制）
13. 密码引擎**不接受任何原始密钥标量**，只收 HSM 句柄；跨域交换的必须是无陷门的 `PublicChameleon`（红线 1 的运行时强制）
14. 陷门碰撞 `.forge(` 全项目**只允许出现在 `crypto/primitives/chameleon.py` 与 `crypto/hsm/soft.py`**（guard R4 强制，crypto 内部与 examples 同样受限）
