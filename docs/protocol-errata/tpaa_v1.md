# tpaa_v1 勘误与决策记录

来源：《TPAA说明书.docx》（与 `TPAA专利(1).zip` 内同一文件）、附图表 1、组会幻灯片（较早版本，仅作补充）。
冲突时以说明书为准（2026-10 用户确认）。

## 原文安全缺陷

| # | 原文 | 问题 | v1 处理 | 测试 |
|---|---|---|---|---|
| S1 | G2 / 算法1：`CCH_sk_tp`、`CCH_sk_ap` 保持 AF 不变，陷门即主私钥 | 用户持有 `r_bind`、`r_bind'`、`r_bind''`，由 `r' = r + sk·(1−x)` 直接解出 `sk_tp`、`sk_ap`（签名 / 解密 / KDF 全部失守） | E1 | `test_spec_literal_user_recovers_tp_master_key`（基线） |
| S2 | G3 本地库 `H(ID) → r_bind` | TP 可按式 3 为每个人重算 AF，不经 AP 把 DID 关联到 H(ID)；D6 时 TP 也直接见到 AF | **未消除**，限界写明：v1 保证 AP 单方揭露不了、R1 必须 AP 交回 s_ap，不保证 TP 单方无法关联 | — |
| K1 | （proto0 实现）随机数 r 公开在 PHC | 同一 APCH 两组公开开口 → TP 还原 AP 变色龙陷门 | E3 | `test_k1_inputs_absent_from_v1_phc`；proto0 现状见 `test_trapdoor_exposure.py` |
| N2 | 表 1：APproof 只签 (APM, APid) | 第三方无 r、验不了 TPCH/APCH，同一 AP 签的另一张凭证的 APM+APproof 可原样拼进来 | APM 新增 `AFRef = H(AF)` | `test_splicing_apm_from_another_credential_is_rejected` |
| N3 | 幻灯片：r_bind 同时用作 Paillier 随机数、ElGamal 随机数、AF 指数 | 用户可剥掉 RF 的随机部分；g1 = n+1 时还可从 ECID 解出 `CID + sk_tp·RF` | 三处各用独立随机数 | 结构保证（supervision.py 每次 seal 自取随机数） |

## 修订规则

| # | 原文 | v1 |
|---|---|---|
| E1 | AF 中的 `pk_ap`、`pk_tp`，陷门为 `sk_ap`、`sk_tp` | 换成**本凭证专用**陷门公钥 `A = g^a`、`T = g^t`，由各自 HSM 按槽位派生（HMAC(root, nonce)）。用户最多解出本凭证的 (a, t)。槽位登记归属人，首次碰撞后绑定到 AF |
| E2 | 每方一把 sk，签名 / ElGamal / 陷门 / KDF / PRF 共用 | 按用途分开：Schnorr 私钥、变色龙私钥、root（派生 CCH 陷门与 PRF） |
| E3 | 表 1 未列随机数 | r_tp、r_ap、r_bind 只存各方本地库，不进 PHC |
| E4 | R1：`s_ap = PRF(sk_tp, AF)` | `PRF(sk_ap, AF)`，与 D4 一致。理由：sk_tp 算出的值减不掉 RF 里的那一项；AP 没有 sk_tp；若 TP 自己能算，"向 AP 请求"这一步没有意义 |
| E5 | 式 6：G2 的 ECID 依赖 D4 才有的 RF | G2 先封 `PEnc(CID)`；D6 按式 6 重封 `PEnc(CID + k_tp(RF))`，`k_tp` 为 TP 的 PRF 派生量（E2） |
| E6 | `PEnc_psk`；解密 `mod n²` | 用公钥 ppk 加密；解密 `mod n` |
| E7 | 算法 2：`PA'`、`PPHC'`，输入写 r_ap | `TPA'`、`PHC'`，输入 r_tp；碰撞保持 TPCH 不变（proto0 是重算 TPCH） |
| E8 | T1 返回"初始 PHC" | 返回最终 PHC''（否则 RE2 拿不到 CMI）；T1 的身份还原走 R1，需要 AP 配合（P6 落地） |
| E9 | HCGen、PAGen 未定义 | HCGen：`c0 = H("HCGen/seed", H(ID))`，`ci = H("HCGen/link", c(i−1), id, ver, digest)`，顺序为功能分类顺序。PAGen：P5 定义为生成签名的 AgentManifest |
| E10 | D2：本地不得有该用户记录 | 按"身份 + selection"查重，允许一人多 PA（V6） |
| E11 | 群参数未给 | Z_p\*：RFC 3526 第 15 组（3072 bit 安全素数），g = 4，在 q 阶子群运算；签名与 TPCH/APCH 用 secp256k1 |
| E12 | 指数里的 IRF（Paillier 密文）、CMI（十六进制串） | 带域分离哈希到 Z_q：`x = H("cch/x", kind, value) mod q` |
| E13 | 原文按字段直接拼接 | 规范化编码：长度前缀 + 类型标记 + 域分离 tag（`crypto/tpaa_v1/encoding.py`） |
| E14 | 式 4 只签 `Sign_ska(r_bind)` | 用户签名覆盖整份请求（CR / AR / PACI / DIDGR）+ requestId + 有效期，防止签名被挪到另一份请求；签名私钥公钥写进 TPAC，AP 由此认证用户 |
| E15 | `EN_pk(x)` 为 ElGamal，未给长消息编码 | ElGamal-KEM + encrypt-then-MAC（DHIES 结构），消息种类 tag 进 KDF，c1 先查子群（`crypto/tpaa_v1/pke.py`）。加密私钥由 HSM root 派生，与签名私钥分开（E2） |
| E16 | `s1 = KDF(λ1, sk_tp·AF)` | `s1 = PRF_tp("s1", AF)`：不复用 Paillier 私钥与签名私钥（E2） |
| E17 | 原文无人工审核 | 审核员（review-service，独立签名密钥）对 CR 摘要签"通过"证据；`tp_issue` 先验证据再做任何密钥动作 |
| E18 | R1 只写"TP 向 AP 请求、AP 同意后返回 s_ap" | 立案 = 两名不同监管员各用个人 STAFF 密钥签 (caseId, DID, purpose)；TP 签协查请求（含两份签字、AF、有效期）；**AP 用自己配置的监管员名录**核对签字后，把 s_ap 封给 TP 的加密公钥返回。取证包封给发起揭露的监管员（`crypto/tpaa_v1/case.py`） |
| E19 | D4 只回 PAR（RF、domain2、PHC'、PA），**没有 AP 对"分配给谁、哪个域名"的签名证据**；D6 直接取 DIDGR 里的 `domain2` 拼 DID | AP 在 D4 追加 `D4Statement`：AP 签名声明 applicationId、recordId、owner、userSignPk、afRef、cmi、domain2、modulesDigest、phcDigest、issuedAt，随 PAR 加密给用户；D5 验 AP 签名并与 PAR 事实逐项比对，之后用户签名覆盖整份声明；D6 只取声明里的 `domain2`，并对 `recordId` 做跨申请一次性消费。理由：用户签名只能证明"这话是用户说的"，不能证明"AP 给过这个域名"——威胁模型里 AP 并非全信（R1 需 AP 配合即为证据），故分配结果不能由用户代述 | `test_d4_statement_attacks.py` |
| N1 | 幻灯片 TPproof = Sign(ASO, TPid) | 按表 1 只签 TPM（签整个 ASO 时 AP 一改 APM，TPproof 即失效） |
| N4 | 字段说明"TP 把 APCH 的陷门发给 AP" | TP 发的是 `EN_pk_ap(r_ap)`（随机数）；AP 的陷门本来就在 AP 手里 |

## v1 仍有的限界

1. **用户能解出本凭证的 (a, t)**，因而能为自己的 AF 造出另一组开口（例如对应别的 CMI）。
   CMI 的真实性由 APproof 签名与 AP 本地存的 CMI 保证，AF 本身对持有者不再是承诺。
2. **AP 的变色龙主私钥仍是所有凭证共用**：TP 签发时知道 r_ap（一组开口）。只要 AP 的
   r_ap'（第二组开口）从不离开 AP，K1 不成立。U3 / RE / 协查接口必须遵守这一点。
3. **槽位归属人由协议层认证**。HSM 只做比对。D1 若不带用户签名，AP 侧归属人只能用 H(ID)，
   而 H(ID) 来自身份证号、熵低 —— P3 必须让 D1 带用户签名。
4. **S2** 见上表。E18 让"TP 拿到 s_ap"需要 AP 认可的两名监管员签字，
   但 TP 手里本来就有 H(ID) → r_bind 的记录（S2），**不靠 s_ap 也能把 DID 关联到 H(ID)**。
   所以 E18 保证的是"走正规揭露流程必须 AP 配合、且在 AP 留痕"，不是"TP 在密码学上无法单方关联"。
5. **DID 长约 6 KB**：`did:wba:<CSCID>` 里的 CSCID 是对 (AF, RF) 的加密，RF 是 4096 bit 的
   Paillier 密文。原文结构如此；若需短 DID，要另定"CSCID 存链下、DID 只放其摘要"的方案（需作者确认）。
6. **D6 时 TP 无法验证 RF 里封的确实是 H(ID) + s_ap**（不知道 s_ap）。错误的 RF 要到 R1 才暴露；
   `tp_reveal` 会用 AF 等式发现它，但那时已经立案。
7. 防重放（requestId 去重）、审批的"双人且不同人"规则在服务层落地（`services/shared/v1_http.py`
   `claim_request_id`、`review-service` `ReviewDesk`），协议层只验签名与有效期。
   审核员身份取自令牌（STAFF 个人密钥登录，`services/shared/v1_auth.py`）。"双人"成立的前提是
   人员名录里一人一把钥匙 —— 这是组织层面的约束，代码只能保证"两把不同的钥匙"。
8. 纯 Python 实现，只用于仿真与单元验证。
9. **`D4Statement.applicationId` 在 AP 侧没有独立核验依据**：申请号由 TP 分配，AR 与 TPAC 里都没有
   （`ap_open_ar` 只读这两样），AP 只能采信门户在 D2 开会话时传入的值。该字段因此只是纵深防御，
   **真正的锚点是 `afRef`** —— D6 把它与本条 G3 记录的 AF 对齐，声明换不到别的申请上去；号填错只让
   D6 拒绝，是自伤而非攻击面。若要升为锚点，需在 G3 的 TPAC body 里加 `applicationId`（TP 签发时已知），
   代价是 TPAC 签名域变化、历史向量重算。当前选择不改。

## 待作者确认

- E5 式 6 的原意（ECID 为何要叠加 `sk_tp·RF`）。
- S2 是否接受为方案限界。
- 式 3 里 H(ID) 作为群元素的映射方式（v1 取 `g^(H(ID) mod q)`）。
