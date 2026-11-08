"""tpaa_v1 协议层对抗用例 —— 每条都是"攻击必须失败"。

    槽位劫持 / 审批证据挪用 / 密文串用 / 冒名 AR / CMM 版本错配 / AP 篡改 CMI /
    冒名 DIDGR / 无案协查 / 错误 s_ap / AP 接触 PII / r_ap' 外泄 / CSCID 越域解密
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_protocol import (  # noqa: E402
    A, APP_ID, BI, CMM, EXP, NOW, PII, REC_ID, SELECTION, T, U, shared, sup_key, v1,
)

from crypto.tpaa_v1.pke import seal  # noqa: E402


def _raises(exc, fn, needle=""):
    try:
        fn()
    except exc as e:
        assert needle in str(e), f"{needle!r} 不在：{e}"
        return
    raise AssertionError(f"预期 {exc.__name__}")


# ---------------------------------------------------------------------------
# G1–G3
# ---------------------------------------------------------------------------


def test_attacker_cannot_drive_victims_slot() -> None:
    """攻击者用受害者的归属人申请槽位，再用自己的密钥签 CR —— 碰撞时归属人对不上。"""
    r = shared()
    p = r.p
    victim = v1.owner_of(p.user.pubkey())
    attacker = v1.make_demo_hsm(domain="USER")
    cr, _ = U.g1_build_cr(user_hsm=attacker, pii=PII, bi=BI, tp_enc_pk=p.tp.enc_pub(),
                          tp_slot=p.tp.allocate_slot(victim), ap_slot=p.ap.allocate_slot(victim),
                          ap_sign_pk=p.ap.pubkey(), request_id="cr-evil", expires=EXP)
    opened = T.tp_open_cr(tp_hsm=p.tp, cr_box=cr, now=NOW)
    appr = T.approve(reviewer_hsm=p.review, cr_digest=opened.cr_digest,
                     reviewers=["rev-a"], expires=EXP)
    _raises(v1.SlotError, lambda: T.tp_issue(
        tp_hsm=p.tp, opened=opened, approval=appr, review_pk=p.review.pubkey(),
        sup_pub=sup_key().public(), storage=p.storage, ap_ch=p.ap.public_chameleon(),
        ap_sign_pk=p.ap.pubkey(), ap_enc_pk=p.ap.enc_pub(), now=NOW), "归属人")


def test_approval_cannot_be_reused_forged_or_stale() -> None:
    r = shared()
    pk = r.p.review.pubkey()
    _raises(v1.ProtocolError, lambda: T.check_approval(
        r.approval, review_pk=pk, cr_digest="00" * 32, now=NOW), "这份申请")
    forger = v1.make_demo_hsm(domain="REVIEW")
    fake = T.approve(reviewer_hsm=forger, cr_digest=r.opened.cr_digest,
                     reviewers=["rev-a"], expires=EXP)
    _raises(v1.ProtocolError, lambda: T.check_approval(
        fake, review_pk=pk, cr_digest=r.opened.cr_digest, now=NOW), "签名无效")
    _raises(v1.ProtocolError, lambda: T.check_approval(
        r.approval, review_pk=pk, cr_digest=r.opened.cr_digest, now="2026-10-15T00:00:00"),
        "过期")


def test_ciphertext_cannot_change_type_or_recipient() -> None:
    r = shared()
    _raises(v1.PkeError, lambda: r.p.tp.pke_open(r.rr, tag="CR"), "类型")
    wrong_tag = dict(r.cr, tag="AR")
    _raises(v1.PkeError, lambda: r.p.ap.pke_open(wrong_tag, tag="AR"), "解密失败")
    _raises(v1.PkeError, lambda: r.p.ap.pke_open(r.cr, tag="CR"), "解密失败")


def test_expired_cr_rejected() -> None:
    r = shared()
    _raises(v1.ProtocolError, lambda: T.tp_open_cr(
        tp_hsm=r.p.tp, cr_box=r.cr, now="2026-10-15T00:00:00"), "过期")


# ---------------------------------------------------------------------------
# D1–D5
# ---------------------------------------------------------------------------


def test_stolen_phc_and_tpac_cannot_be_presented_by_someone_else() -> None:
    """攻击者拿到受害者的 PHC + TPAC，用自己的钥匙签 AR —— TPAC 里认证过的是受害者的公钥。"""
    r = shared()
    attacker = v1.make_demo_hsm(domain="USER")
    ar = U.d1_build_ar(user_hsm=attacker, cred=r.cred, ap_enc_pk=r.p.ap.enc_pub(),
                       request_id="ar-evil", expires=EXP)
    _raises(v1.ProtocolError, lambda: A.ap_open_ar(
        ap_hsm=r.p.ap, ar_box=ar, tp_sign_pk=r.p.tp.pubkey(), now=NOW), "AR 用户")


def test_paci_bound_to_cmm_version_and_catalog() -> None:
    r = shared()
    old = U.d3_build_paci(user_hsm=r.p.user, ap_enc_pk=r.p.ap.enc_pub(),
                          cmm_version="cmm-old", selection=SELECTION, request_id="p2")
    _raises(v1.ProtocolError, lambda: A.ap_build(
        ap_hsm=r.p.ap, session=r.sess, paci_box=old, cmm_version=CMM["version"],
        resolve=lambda s: [], sup_pub=sup_key().public(), domain2="ap.example", now=NOW,
        application_id=APP_ID, record_id=REC_ID),
        "CMM 版本")


def test_user_detects_ap_swapping_module_code() -> None:
    """AP 交付的 PA 里换了一个模块（摘要不同）—— 用户重算 CMI 对不上。"""
    r = shared()
    par = r.p.user.pke_open(r.par, tag="PAR")
    par["PA"]["modules"][1]["digest"] = "ee" * 32
    forged = seal(r.p.user.enc_pub(), par, tag="PAR")
    _raises(v1.ProtocolError, lambda: U.d5_accept_par(
        user_hsm=r.p.user, par_box=forged, cred=r.cred, application_id=APP_ID,
        **r.p.keys), "CMI")


def test_user_detects_wrong_r_bind2() -> None:
    r = shared()
    par = r.p.user.pke_open(r.par, tag="PAR")
    par["rBind2"] = format(int(par["rBind2"], 16) + 1, "x")
    forged = seal(r.p.user.enc_pub(), par, tag="PAR")
    _raises(v1.ProtocolError, lambda: U.d5_accept_par(
        user_hsm=r.p.user, par_box=forged, cred=r.cred, application_id=APP_ID,
        **r.p.keys), "绑定关系")


# ---------------------------------------------------------------------------
# D6
# ---------------------------------------------------------------------------


def test_didgr_from_another_user_rejected() -> None:
    r = shared()
    attacker = v1.make_demo_hsm(domain="USER")
    g = U.d5_build_didgr(user_hsm=attacker, verified=r.verified, tp_enc_pk=r.p.tp.enc_pub(),
                         request_id="g-evil", expires=EXP)
    _raises(v1.ProtocolError, lambda: T.tp_finalize(
        tp_hsm=r.p.tp, didgr_box=g, rec=r.trec, sup_pub=sup_key().public(),
        tp_sign_pk=r.p.tp.pubkey(), ap_sign_pk=r.p.ap.pubkey(), domain1="tp.example",
        now=NOW, application_id=APP_ID), "持有人")


def test_didgr_without_algorithm1_rejected() -> None:
    """跳过 AP 直接拿初始 PHC 去要 DID —— 拒绝（D5 回执不能代替 D4）。"""
    r = shared()
    body = {"RF": "1", "domain2": "ap.example", "PHC": r.cred.phc, "requestId": "g0",
            "expires": EXP, "userSignPk": v1.tp.pk_hex(r.p.user.pubkey())}
    from crypto.tpaa_v1.wire import json_digest, sign
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: T.tp_finalize(
        tp_hsm=r.p.tp, didgr_box=box, rec=r.trec, sup_pub=sup_key().public(),
        tp_sign_pk=r.p.tp.pubkey(), ap_sign_pk=r.p.ap.pubkey(), domain1="tp.example",
        now=NOW, application_id=APP_ID), "算法1")


# ---------------------------------------------------------------------------
# R1 / R2 与数据边界
# ---------------------------------------------------------------------------


def test_ap_refuses_unauthorised_assist() -> None:
    r = shared()
    _raises(v1.ProtocolError, lambda: A.ap_assist(
        ap_hsm=r.p.ap, af=r.arec.af.af, case_ok=False), "未获授权")


def test_reveal_with_wrong_s_ap_detected() -> None:
    r = shared()
    _, rf = T.tp_open_did(tp_hsm=r.p.tp, did=r.did)
    _raises(v1.ProtocolError, lambda: T.tp_reveal(
        sup_key=sup_key(), rf=rf, s_ap=12345, rec=r.trec2), "R1")


def test_only_tp_can_open_cscid() -> None:
    r = shared()
    from crypto.tpaa_v1.wire import unb64u
    box = unb64u(r.did.split(":")[2])
    _raises(v1.PkeError, lambda: r.p.ap.pke_open(box, tag="CSCID"))
    assert format(r.arec.af.af, "x") not in r.did, "DID 里不能有明文 AF"


def test_ap_never_sees_pii_or_bi() -> None:
    r = shared()
    seen = json.dumps(r.p.ap.pke_open(r.ar, tag="AR"), ensure_ascii=False)
    seen += json.dumps(r.p.ap.pke_open(r.paci, tag="PACI"), ensure_ascii=False)
    for s in (PII["ID"], PII["name"], PII["phone"], BI["iris"]):
        assert s not in seen, f"AP 可见材料里出现了 {s}"


def test_r_ap_prime_never_leaves_ap() -> None:
    """errata 限界 2：r_ap' 一旦外发，TP 手里的 r_ap 就构成第二组开口（K1）。"""
    r = shared()
    leak = format(r.arec.r_ap, "x")
    for box, hsm, tag in ((r.par, r.p.user, "PAR"), (r.didgr, r.p.tp, "DIDGR"),
                          (r.final, r.p.user, "FINAL")):
        assert leak not in json.dumps(hsm.pke_open(box, tag=tag)), tag
