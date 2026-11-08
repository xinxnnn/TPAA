# tpaa_v1 公式 → 代码 → 测试

修订依据见 [../protocol-errata/tpaa_v1.md](../protocol-errata/tpaa_v1.md)。
代码均在 `crypto/tpaa_v1/` 与 `crypto/hsm/v1.py`，业务侧经 `crypto.sdk.v1`。
测试：`tests/unit/test_tpaa_v1.py`（U）、`tests/adversarial/test_tpaa_v1_attacks.py`（A）、
`tests/unit/test_tpaa_v1_protocol.py`（P）、`tests/adversarial/test_tpaa_v1_protocol_attacks.py`（PA）。
协议层按参与方分文件：`proto_user.py` / `proto_tp.py` / `proto_ap.py`，函数只做"收密文 → 验 → 发密文 + 本地记录"，不做 I/O。

| 步骤 | 原文 | v1 | 代码 | 测试 | 状态 |
|---|---|---|---|---|---|
| 初始化 | pp = {g,p,G,q,E,n,g1}；各方 sk/pk/cpk | E2 / E11 | `params.py`、`hsm/v1.py` | U `test_params_are_safe_prime_group` | ✅ |
| G1 | 式 3 `AF = H(ID)·pk_ap·pk_tp·g^r` | E1：`h(ID)·A·T·g^r` | `engine.commit_af` | U `test_af_constant_across_g1_g2_d4` | ✅ |
| G1 | 式 4 CR（ElGamal + Sign_ska(r_bind)） | E14 / E15 | `proto_user.g1_build_cr`、`proto_tp.tp_open_cr`、`pke.py` | P `test_g4_*`；PA `test_expired_cr_rejected`、`test_ciphertext_*` | ✅ |
| 审核 | （原文无） | E17 | `proto_tp.approve / check_approval` | PA `test_approval_cannot_be_reused_forged_or_stale` | ✅ |
| G2 | 式 5 `IRF = g1^H(ID)·r1^n` | E6 | `supervision.compute_irf` | U `test_r1_reveal_needs_s_ap` | ✅ |
| G2 | `CCH_sk_tp(1, r, IRF) → r'` | E1 / E12 | `engine.rebind_af(kind="IRF")` | U `test_af_constant…`；A `test_slot_*` | ✅ |
| G2 | `s1 = KDF(λ1, sk_tp·AF)`、SecInfo | E16 | `proto_tp.tp_issue`（`_s1`） | P `test_ipfs_only_holds_ciphertext`、`test_r2_*` | ✅ |
| G2 | 式 6 ECID（第一段） | E5 | `supervision.seal_ecid` | U `test_r2_ecid_two_stage` | ✅ |
| G3 | TPM / TPproof / TPCH / APCH / CHproof | E3 / E13 / N1 | `engine.issue_phc`、`schema.py` | U `test_issue_and_algorithms_verify_publicly` | ✅ |
| G3 | 式 7 TPAC | E14 | `proto_tp.tp_issue` | PA `test_stolen_phc_and_tpac_*` | ✅ |
| G4 | 用户核验 PHC / TPAC / AF | — | `proto_user.g4_accept_rr` | P `test_g4_wallet_holds_verified_initial_phc` | ✅ |
| D1–D3 | AR / CMM / PACI | E14 | `proto_user.d1_* / d3_*`、`proto_ap.ap_open_ar / ap_send_cmm` | PA `test_paci_bound_to_cmm_version_and_catalog` | ✅ |
| D4 | 式 8 CMI = HCGen(CMC, H(ID)) | E9 | `engine.hcgen` | U `test_hcgen_binds_identity_order_and_content` | ✅ |
| D4 | 算法 1（APM / APproof / APCH 碰撞） | N2 AFRef | `engine.algorithm1` | U `test_algorithm1_keeps_apch_and_chproof`；A `test_splicing…` | ✅ |
| D4 | 算法 1 第 11–13 行（AF 重绑 CMI） | E1 / E12 | `engine.rebind_af(kind="CMI")` | U `test_af_constant…` | ✅ |
| D4 | `s_ap = PRF(sk_ap, AF)`；式 9 RF | E4 | `supervision.compute_s_ap / compute_rf` | U `test_s_ap_is_prf_of_ap_and_af` | ✅ |
| D5 | 用户重算 CMI 与 AF | — | `proto_user.d5_accept_par / d5_build_didgr` | P `test_d5_*`；PA `test_user_detects_*` | ✅ |
| D6 | SCID / CSCID / did:wba / CDID | E15 | `proto_tp.tp_finalize`、`proto_user.d6_accept_final` | P `test_d6_*`；PA `test_didgr_*`、`test_only_tp_can_open_cscid` | ✅ |
| D6 | 算法 2（CDID / TPproof / TPCH 碰撞） | E7 | `engine.algorithm2` | U `test_algorithm2_keeps_tpch_and_chproof` | ✅ |
| D6 | 式 6 ECID（第二段） | E5 | `supervision.ecid_mask / seal_ecid(mask=)` | U `test_r2_ecid_two_stage` | ✅ |
| R1 | `H(ID) = PDec(RF) − s_ap` | E4 / E6 | `supervision.reveal_hid` | U `test_r1_reveal_needs_s_ap` | ✅ |
| R1 | 协议编排：解 CSCID → AP 协作 → 核对 AF | E4 | `proto_tp.tp_open_did / tp_reveal`、`proto_ap.ap_assist` | P `test_r1_reveal_with_ap_assist`；PA `test_reveal_with_wrong_s_ap_detected` | ✅ |
| R1 授权 | （原文无） | E18 | `case.py`、`supervision-service/v1_app.py`、`agent-service/v1_app.py` `/v1/tpaa/assist` | I `test_full_trace_chain_over_http`、`test_ap_refuses_when_tp_side_signers_*`、`test_ap_assist_endpoint_rejects_*` | ✅ |
| R2 | ECID → CID → SecInfo | E5 / E16 | `proto_tp.tp_recover_pii` | P `test_r2_recovers_pii_through_resealed_ecid` | ✅ |
| 校验 | 第三方（只用公钥） | N2 | `engine.verify_public` | U / A 多项 | ✅ |
| 校验 | 持有方（TP/AP 用自己的 r） | E3 | `engine.verify_holder` | U `test_holders_can_open_their_own_chameleon_hash` | ✅ |
| RE / U / T | 3.1–3.3 | E8 / E10 | — | — | ⏳ P6 |
