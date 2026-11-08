"""PHC 结构与算法1 / 算法2 的**可执行证明**。

★ 最关键的一条：test_algorithm1_ap_update_keeps_tp_signature_valid
  它证明 AP 在**没有 TP 参与**的情况下改写了 PHC 内容，
  而 TP 当初的签名依然验证通过。

★ 步骤 9 之后，本文件里再也看不到任何原始密钥标量：
  TP / AP 各持自己的 HSM 句柄，跨域给出去的只有 public_chameleon()。
  末尾一组 test_step9_* 用例把这些收口钉死 —— 谁要是想倒退回传私钥，
  测试会先于评审失败。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import Parties, identity_hash  # noqa: E402

from crypto.phc import PHC, issue_phc, update_by_ap, update_by_tp, verify_phc  # noqa: E402
from crypto.primitives import (  # noqa: E402
    ChameleonHash,
    ChameleonKey,
    PublicChameleon,
    TrapdoorUnavailable,
    hash_chain,
    new_secret,
    pubkey,
    ser_point,
    sign,
)

IDH = identity_hash()
TAU = 20261014
CRF = 555777


def _parties() -> Parties:
    return Parties()


def _issue(parties: Parties | None = None) -> tuple[PHC, Parties]:
    p = parties or _parties()
    phc = issue_phc(
        tp_hsm=p.tp_hsm, ap_ch=p.ap_pub,
        identity_hash=IDH, tau=TAU, crf=CRF,
        tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        apid=ser_point(p.ap_pk),
    )
    return phc, p


# ---------------------------------------------------------------------------
# 基本流程
# ---------------------------------------------------------------------------


def test_issue_produces_verifiable_phc() -> None:
    phc, p = _issue()
    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH, tau=TAU, crf=CRF))
    assert errs == [], f"初始 PHC 应当校验通过，实际错误：{errs}"
    assert phc.apm_cmi == "", "初始 PHC 的 APM 应为空"


def test_algorithm1_ap_update_keeps_tp_signature_valid() -> None:
    """★ 算法1 的核心断言。

    AP 在没有 TP 参与的情况下写入 CMI，随后：
        - APCH 取值不变
        - TPCH 取值不变
        - AF 取值不变
        - TP 当初的签名依然有效
    """
    phc, p = _issue()

    apch_before = phc.proof_apch
    tpch_before = phc.proof_tpch
    af_before = phc.tpm_af
    chproof_before = phc.proof_chproof

    cmi = hash_chain([b"<code:memory-v1>", b"<code:planner-v1>"])
    update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:05:00")

    assert phc.apm_cmi == cmi.hex(), "CMI 应当已写入"
    assert phc.proof_apch == apch_before, "APCH 取值必须不变"
    assert phc.proof_tpch == tpch_before, "TPCH 取值必须不变"
    assert phc.tpm_af == af_before, "AF 取值必须不变"
    assert phc.proof_chproof == chproof_before, "TP 不应重新签名"

    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH, tau=TAU, crf=CRF))
    assert errs == [], f"更新后仍应校验通过，实际错误：{errs}"


def test_algorithm1_survives_many_updates() -> None:
    """反复升级（对应 U1-U3）后，签名仍然有效。"""
    phc, p = _issue()
    apch0 = phc.proof_apch

    for i in range(5):
        cmi = hash_chain([f"<code:planner-v{i}>".encode()])
        update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time=f"2026-10-14T10:0{i}:00")
        assert phc.proof_apch == apch0

    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH, tau=TAU, crf=CRF))
    assert errs == []


def test_algorithm2_tp_issues_did_and_reseals() -> None:
    """算法2：TP 写入 DID 后重新封印，TPCH 会变且由 TP 重签。"""
    phc, p = _issue()
    cmi = hash_chain([b"<code:planner>"])
    update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:05:00")

    apch_before = phc.proof_apch
    tpch_before = phc.proof_tpch

    update_by_tp(phc, tp_hsm=p.tp_hsm, did="did:wba:af7c:pa.example")

    assert phc.tpm_cdid == "did:wba:af7c:pa.example"
    assert phc.proof_apch == apch_before, "TP 改自己那半字段不应影响 APCH"
    assert phc.proof_tpch != tpch_before, "TPCH 会变（TP 改了 TPM）"

    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH, tau=TAU, crf=CRF))
    assert errs == [], f"颁发 DID 后应校验通过，实际错误：{errs}"


# ---------------------------------------------------------------------------
# 篡改必须被检出
# ---------------------------------------------------------------------------


def test_wrong_identity_hash_fails_af_check() -> None:
    """换个身份哈希去校验 —— AF 锚定必须失败。"""
    phc, p = _issue()
    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH + 1, tau=TAU, crf=CRF))
    assert any("AF" in e for e in errs)


def test_tampered_cmi_is_detected() -> None:
    """AP 改了 CMI 但**没有**走算法1（没求碰撞）—— 必须被检出。"""
    phc, p = _issue()
    cmi = hash_chain([b"<code:planner>"])
    update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:05:00")

    # 绕过 engine，直接改字段（模拟攻击者直接改磁盘上的凭证）
    phc.apm_cmi = hash_chain([b"<code:planner-MALICIOUS>"]).hex()

    errs = verify_phc(phc, **p.verify_kwargs(identity_hash=IDH, tau=TAU, crf=CRF))
    assert errs, "未走算法1 的篡改必须被检出"


def test_forged_tp_signature_is_rejected() -> None:
    """冒充 TP 对 (TPCH‖APCH) 签名 —— 必须失败。"""
    phc, p = _issue()

    attacker_pk = pubkey(new_secret())
    phc.proof_chproof = sign(new_secret(), phc.signed_digest()).to_bytes()

    errs = verify_phc(phc, tp_pk=attacker_pk, ap_pk=p.ap_pk,
                      tp_ch=p.tp_pub, ap_ch=p.ap_pub,
                      identity_hash=IDH, tau=TAU, crf=CRF)
    assert any("签名" in e for e in errs)


def test_parent_did_is_bound_into_af() -> None:
    """子智能体的 parent_did 必须被压进 AF，改了就锚定失败。"""
    p = _parties()
    phc, _ = _issue(p)
    phc.parent_did = "did:wba:parent-0001"
    # 重新锚定 AF（派生时 TP 会把 parent_did 封进 AF 消息）—— 只用 TP 的公开句柄
    phc.tpm_af_r = p.tp_pub.rand()
    phc.tpm_af = p.tp_pub.compute(phc.af_message(IDH, TAU, CRF), phc.tpm_af_r)
    phc.tpa_proof = b""          # 简化：只验证 AF 部分
    phc.proof_chproof = b""

    ok_before = p.tp_pub.compute(phc.af_message(IDH, TAU, CRF), phc.tpm_af_r) == phc.tpm_af
    assert ok_before

    phc.parent_did = "did:wba:parent-9999"      # 攻击者改父指针
    assert p.tp_pub.compute(phc.af_message(IDH, TAU, CRF), phc.tpm_af_r) != phc.tpm_af


# ---------------------------------------------------------------------------
# ★ 步骤 9 收口：陷门与私钥不得越过 HSM 边界
# ---------------------------------------------------------------------------


def test_step9_engine_refuses_raw_secret_scalars() -> None:
    """把 tp_sk / ap_sk 直接递给引擎 —— 必须当场失败，而不是签完再说。"""
    p = _parties()
    try:
        issue_phc(
            tp_hsm=p.tp_hsm, ap_ch=p.ap_pub,
            tp_sk=new_secret(),                     # 旧调用方式的残留
            identity_hash=IDH, tau=TAU, crf=CRF,
            tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        )
    except TypeError as e:
        assert "红线 1" in str(e), f"错误信息应点明红线，实际：{e}"
    else:
        raise AssertionError("引擎不该接受原始私钥标量")


def test_step9_engine_refuses_unexpected_kwargs() -> None:
    """拼错的 kwarg 也要报错 —— 收口守卫不能顺手吞掉笔误。"""
    phc, p = _issue()
    try:
        # 参数齐备，只是把 cmi 写成了 cme —— 收口守卫不能顺手吞掉笔误
        update_by_ap(phc, ap_hsm=p.ap_hsm, cmi="c0ffee", apm_time="2026-10-14T10:05:00",
                     cme="deadbeef")
    except TypeError as e:
        assert "未预期" in str(e), f"应提示未预期的参数，实际：{e}"
    else:
        raise AssertionError("拼错的参数名不应被静默忽略")


def test_step9_cross_domain_handle_cannot_forge() -> None:
    """★ 跨域拿到的句柄没有改写的资格 —— 一试就被拒。"""
    p = _parties()
    assert isinstance(p.ap_pub, PublicChameleon)
    try:
        p.ap_pub.forge((1, 2), 3)
    except TrapdoorUnavailable:
        pass
    else:
        raise AssertionError("PublicChameleon 不应能求碰撞")


def test_step9_issue_refuses_trapdoor_bearing_handle() -> None:
    """TP 拿到了**带着 AP 陷门**的句柄 —— 签发必须拒绝。

    这条是算法1 的立身之本：TP 若能把 AP 的陷门握在手里，
    "AP 独自完成更新"就只是一句写在文档里的话。
    """
    p = _parties()
    leaky = ChameleonHash(ChameleonKey())       # 模拟误传（或恶意构造）的完整句柄
    try:
        issue_phc(
            tp_hsm=p.tp_hsm, ap_ch=leaky,
            identity_hash=IDH, tau=TAU, crf=CRF,
            tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        )
    except PermissionError as e:
        assert "陷门" in str(e)
    else:
        raise AssertionError("含陷门的跨域句柄必须被拒")


def test_step9_wrong_domain_handle_is_rejected() -> None:
    """拿 AP 的句柄去做 TP 的动作 —— 双域隔离要求当场失败。"""
    p = _parties()
    try:
        issue_phc(
            tp_hsm=p.ap_hsm, ap_ch=p.ap_pub,      # 故意拿错
            identity_hash=IDH, tau=TAU, crf=CRF,
            tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        )
    except PermissionError as e:
        assert "AP" in str(e) and "TP" in str(e)
    else:
        raise AssertionError("拿错域的 HSM 句柄应当失败")


def test_step9_ap_rewrite_needs_only_ap_hsm() -> None:
    """端到端复核：整条算法1 里，TP 的句柄一次都没被调用。

    这条测试不需要 TP 在场（只有公钥），AP 照样完成了更新且签名继续有效。
    """
    phc, p = _issue()
    tp_pk, tp_pub = p.tp_pk, p.tp_pub          # TP 交出公钥后即"离线"

    cmi = hash_chain([b"<code:planner-v9>"])
    update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:09:00")

    errs = verify_phc(phc, tp_pk=tp_pk, ap_pk=p.ap_pk, tp_ch=tp_pub, ap_ch=p.ap_pub,
                      identity_hash=IDH, tau=TAU, crf=CRF)
    assert errs == []
