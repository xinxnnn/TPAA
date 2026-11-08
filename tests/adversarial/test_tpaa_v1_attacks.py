"""tpaa_v1 对抗测试 —— 每条对应 errata 里的一项风险。

    S1   原文直译：用户由 (r_bind, r_bind') 解出 TP 主私钥            —— 基线，钉住原文缺陷
    E1   v1：用户最多解出本凭证的 CCH 陷门，解不出主私钥 / 别人的陷门
    E1'  v1：槽位归属与 AF 绑定挡住"借别人的槽位求碰撞"
    N2   v1：别的凭证的 APM + APproof 搬不进来（AFRef）
    E3   v1：PHC 里没有随机数，K1（两组公开开口还原陷门）的输入不存在
    其他：篡改 CMI / 错误的 r_ap / 跨域句柄
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_flow import HID, OWNER, pub_keys, run, v1  # noqa: E402

from crypto.tpaa_v1 import cch  # noqa: E402
from crypto.tpaa_v1.params import G, P, Q, rand_exp  # noqa: E402

_F = None


def _flow():
    global _F
    if _F is None:
        _F = run()
    return _F


def _raises(exc, fn, needle=""):
    try:
        fn()
    except exc as e:
        assert needle in str(e), f"{needle!r} 不在 {e}"
        return
    raise AssertionError(f"预期 {exc.__name__}")


# ---------------------------------------------------------------------------
# S1 基线：原文的陷门就是主私钥
# ---------------------------------------------------------------------------


def test_spec_literal_user_recovers_tp_master_key() -> None:
    """按说明书原文：pk_tp = g^sk_tp 直接进 AF，CCH 用 sk_tp 求碰撞。"""
    sk_tp, sk_ap = rand_exp(), rand_exp()
    pk_tp, pk_ap = pow(G, sk_tp, P), pow(G, sk_ap, P)
    r = rand_exp()
    x_t = cch.exponent_of("IRF", 123456789)
    af0 = cch.af_value(hid=HID, a_pub=pk_ap, t_pub=pk_tp, x_a=1, x_t=1, r=r)
    r1 = cch.collide_r(sk_tp, 1, x_t, r)                    # TP 的 G2
    assert af0 == cch.af_value(hid=HID, a_pub=pk_ap, t_pub=pk_tp, x_a=1, x_t=x_t, r=r1)

    # r' = r + sk·(1 − x_t)  ⇒  sk = (r' − r)/(1 − x_t)；用户只用 r, r', x_t
    recovered = (r1 - r) * pow(1 - x_t, -1, Q) % Q
    assert recovered == sk_tp, "原文结构下用户必然解出 TP 主私钥（errata S1）"


# ---------------------------------------------------------------------------
# E1：v1 下用户能解出的只是本凭证的陷门
# ---------------------------------------------------------------------------


def _user_recovers(f):
    t = (f.af_g2.r - f.af_g1.r) * pow(1 - f.af_g2.x_t, -1, Q) % Q
    a = (f.af_d4.r - f.af_g2.r) * pow(1 - f.af_d4.x_a, -1, Q) % Q
    return t, a


def test_v1_user_recovers_only_this_credentials_trapdoors() -> None:
    f = _flow()
    t, a = _user_recovers(f)
    assert pow(G, t, P) == f.af_g1.t_pub and pow(G, a, P) == f.af_g1.a_pub, \
        "限界：用户确实能解出本凭证的 (t, a) —— 写在 errata 里"

    # 解出来的不是任何主密钥
    assert t not in (f.tp._schnorr_sk, f.tp._chameleon.sk)        # noqa: SLF001
    assert a not in (f.ap._schnorr_sk, f.ap._chameleon.sk)        # noqa: SLF001

    # 同一对 HSM 给别人发的凭证，陷门互不相同
    other = run(tp=f.tp, ap=f.ap, hid=HID + 7, owner="user-pk-fpr:other")
    t2, a2 = _user_recovers(other)
    assert (t2, a2) != (t, a)
    assert pow(G, t, P) != other.af_g1.t_pub


def test_v1_master_signing_keys_still_sound_after_user_recovery() -> None:
    """用户拿着 (t, a) 也伪造不了 TP 的签名：签名私钥与 CCH 陷门是两把钥匙。"""
    f = _flow()
    forged = replace(f.phc_d6, tpm=replace(f.phc_d6.tpm, cdid="did:wba:evil"))
    errs = v1.verify_public(forged, **pub_keys(f))
    assert "TPproof 无效" in errs


# ---------------------------------------------------------------------------
# E1'：借别人的槽位
# ---------------------------------------------------------------------------


def test_slot_cannot_be_used_by_another_owner() -> None:
    f = _flow()
    _raises(v1.SlotError, lambda: v1.rebind_af(
        f.af_g1, hsm=f.tp, hid=HID, nonce=f.tp_nonce, owner="attacker",
        kind="IRF", value=f.irf), "归属人")


def test_slot_cannot_be_reused_for_a_different_af() -> None:
    """同一个归属人，拿已绑定的槽位去给另一个 AF 求碰撞 —— 拒绝。"""
    f = _flow()
    a_pub, t_pub = f.af_g1.a_pub, f.af_g1.t_pub
    other = v1.commit_af(hid=HID, a_pub=a_pub, t_pub=t_pub, r=rand_exp())
    _raises(v1.SlotError, lambda: v1.rebind_af(
        other, hsm=f.tp, hid=HID, nonce=f.tp_nonce, owner=OWNER,
        kind="IRF", value=f.irf), "另一张凭证")


def test_unknown_slot_rejected() -> None:
    f = _flow()
    _raises(v1.SlotError, lambda: f.tp.slot_public("tp-not-a-real-slot"), "不存在")


# ---------------------------------------------------------------------------
# N2：拼接
# ---------------------------------------------------------------------------


def test_splicing_apm_from_another_credential_is_rejected() -> None:
    f = _flow()
    other = run(tp=f.tp, ap=f.ap, hid=HID + 11, owner="user-pk-fpr:splice")
    spliced = replace(f.phc_d6, apm=other.phc_d6.apm, approof=other.phc_d6.approof)
    errs = v1.verify_public(spliced, **pub_keys(f))
    assert any("AFRef" in e for e in errs), errs


# ---------------------------------------------------------------------------
# E3：K1 的输入在 v1 里不存在
# ---------------------------------------------------------------------------


def test_k1_inputs_absent_from_v1_phc() -> None:
    """proto0 的 K1 需要两组公开的 (APCH 消息, r)。v1 的 PHC 里根本没有 r。"""
    f = _flow()
    for phc in (f.issued.phc, f.phc_d4, f.phc_d6):
        doc = json.dumps(v1.to_jsonld(phc))
        for r in (f.issued.r_ap, f.r_ap1, f.issued.r_tp, f.r_tp1):
            assert format(r, "x") not in doc


# ---------------------------------------------------------------------------
# 篡改 / 越权
# ---------------------------------------------------------------------------


def test_tampered_cmi_fails() -> None:
    f = _flow()
    bad = replace(f.phc_d6, apm=replace(f.phc_d6.apm, cmi="ee" * 32))
    assert "APproof 无效" in v1.verify_public(bad, **pub_keys(f))


def test_wrong_r_ap_cannot_run_algorithm1() -> None:
    f = _flow()
    _raises(ValueError, lambda: v1.algorithm1(
        f.issued.phc, ap_hsm=f.ap, r_ap=f.issued.r_ap + 1, cmi="00", time="t"), "r_ap")


def test_issue_rejects_trapdoor_handle() -> None:
    f = _flow()
    _raises(PermissionError, lambda: v1.issue_phc(
        tp_hsm=f.tp, ap_ch=f.ap._chameleon_hash, ap_pk=f.ap.pubkey(),   # noqa: SLF001
        af=f.af_g2.af, ecid="", time="t"), "红线 1")


def test_cross_domain_algorithm_calls_rejected() -> None:
    f = _flow()
    _raises(PermissionError, lambda: v1.algorithm1(
        f.issued.phc, ap_hsm=f.tp, r_ap=f.issued.r_ap, cmi="00", time="t"))
    _raises(PermissionError, lambda: v1.algorithm2(
        f.phc_d4, tp_hsm=f.ap, r_tp=f.issued.r_tp, cdid="x", time="t"))


def test_af_rejects_non_subgroup_public() -> None:
    _raises(ValueError, lambda: cch.af_value(
        hid=HID, a_pub=P - 1, t_pub=G, x_a=1, x_t=1, r=1), "子群")
