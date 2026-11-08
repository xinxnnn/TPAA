"""D4Statement 攻击面：D5 验签比对、D6 绑定、跨申请复用。

被这组用例钉死的那个旧漏洞：D6 以前从 DIDGR 的 `domain2` 字段直接取 AP 域名。
那是用户递过来的值 —— 用户签名覆盖它，但"AP 到底分配了哪个域名"没有证据。
改一个字段，TP 就会把 DID 签到另一个 AP 域名下，而所有签名都还验得过。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_protocol import (  # noqa: E402
    A, APP_ID, CMM, EXP, NOW, REC_ID, SELECTION, T, U, resolve, shared, sup_key, v1,
)

from crypto.tpaa_v1.pke import seal  # noqa: E402
from crypto.tpaa_v1.wire import json_digest, sign  # noqa: E402


def _raises(exc, fn, needle=""):
    try:
        fn()
    except exc as e:
        assert needle in str(e), f"{needle!r} 不在：{e}"
        return
    raise AssertionError(f"预期 {exc.__name__}，但没有抛出")


def _finalize(r, didgr, *, app_id=APP_ID, rec=None):
    return T.tp_finalize(tp_hsm=r.p.tp, didgr_box=didgr, rec=rec or r.trec,
                         sup_pub=sup_key().public(), tp_sign_pk=r.p.tp.pubkey(),
                         ap_sign_pk=r.p.ap.pubkey(), domain1="tp.example", now=NOW,
                         application_id=app_id)


def _par_fields(r):
    return r.p.user.pke_open(r.par, tag="PAR")


def _reseal_par(r, par):
    return seal(r.p.user.enc_pub(), par, tag="PAR")


def _accept(r, par_box, *, app_id=APP_ID):
    return U.d5_accept_par(user_hsm=r.p.user, par_box=par_box, cred=r.cred,
                           application_id=app_id, **r.p.keys)


# ---------------------------------------------------------------------------
# D4：声明本身的形状
# ---------------------------------------------------------------------------


def test_statement_is_present_and_signed_by_ap() -> None:
    r = shared()
    st = _par_fields(r)["D4Statement"]
    body = A.check_d4_statement(st, ap_sign_pk=r.p.ap.pubkey())
    assert body["applicationId"] == APP_ID
    assert body["recordId"] == REC_ID
    assert body["domain2"] == "ap.example"
    assert body["cmi"] == r.verified.cmi
    assert body["afRef"] == v1.af_ref(r.verified.cred.af.af)
    # 模块摘要对顺序敏感：换序就是另一份配置
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in r.verified.pa["modules"]]
    assert body["modulesDigest"] == A.modules_digest(mods)
    assert A.modules_digest(list(reversed(mods))) != body["modulesDigest"]


def test_statement_signed_by_non_ap_key_is_rejected() -> None:
    """自己造一把 AP 域 HSM 签声明 —— 公钥对不上。"""
    r = shared()
    rogue = v1.make_demo_hsm(domain="AP")
    st = A.d4_statement(ap_hsm=rogue, application_id=APP_ID, record_id=REC_ID,
                        owner=r.verified.statement["owner"],
                        user_sign_pk=r.verified.statement["userSignPk"],
                        af=r.verified.cred.af.af, cmi=r.verified.cmi, domain2="evil.example",
                        modules=[(m["moduleId"], m["version"], m["digest"])
                                 for m in r.verified.pa["modules"]],
                        phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    _raises(v1.ProtocolError, lambda: A.check_d4_statement(st, ap_sign_pk=r.p.ap.pubkey()),
            "AP D4 声明")


def test_statement_requires_application_and_record_id() -> None:
    r = shared()
    for app_id, rec_id in (("", REC_ID), (APP_ID, "")):
        _raises(v1.ProtocolError, lambda a=app_id, b=rec_id: A.d4_statement(
            ap_hsm=r.p.ap, application_id=a, record_id=b, owner="o", user_sign_pk="pk",
            af=1, cmi="c", domain2="ap.example", modules=[], phc1_digest="d", now=NOW),
            "必须绑定")


def test_statement_with_missing_field_is_rejected() -> None:
    r = shared()
    for field in A.STATEMENT_FIELDS:
        broken = {k: v for k, v in _par_fields(r)["D4Statement"].items() if k != field}
        _raises(v1.ProtocolError,
                lambda b=broken: A.check_d4_statement(b, ap_sign_pk=r.p.ap.pubkey()),
                "缺字段")


# ---------------------------------------------------------------------------
# D5：声明必须与 PAR 的实际内容一致
# ---------------------------------------------------------------------------


def test_d5_rejects_par_without_statement() -> None:
    r = shared()
    par = _par_fields(r)
    par.pop("D4Statement")
    _raises(v1.ProtocolError, lambda: _accept(r, _reseal_par(r, par)), "缺字段")


def test_d5_rejects_domain2_swap_outside_statement() -> None:
    """PAR 的明文 domain2 被改，声明里的没改 —— D5 比对时发现不一致。"""
    r = shared()
    par = _par_fields(r)
    par["domain2"] = "evil.example"
    _raises(v1.ProtocolError, lambda: _accept(r, _reseal_par(r, par)), "domain2")


def test_d5_rejects_statement_for_another_application() -> None:
    r = shared()
    _raises(v1.ProtocolError, lambda: _accept(r, r.par, app_id="app-other"),
            "不是针对本次申请")


def test_d5_rejects_statement_bound_to_another_user() -> None:
    """AP 给的声明写着别人的 owner / 公钥 —— 用户自己就该拒收。"""
    r = shared()
    other = v1.make_demo_hsm(domain="USER")
    par = _par_fields(r)
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in par["PA"]["modules"]]
    par["D4Statement"] = A.d4_statement(
        ap_hsm=r.p.ap, application_id=APP_ID, record_id=REC_ID,
        owner=v1.owner_of(other.pubkey()), user_sign_pk=v1.pk_hex(other.pubkey()),
        af=r.verified.cred.af.af, cmi=r.verified.cmi, domain2=par["domain2"],
        modules=mods, phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    _raises(v1.ProtocolError, lambda: _accept(r, _reseal_par(r, par)), "owner")


def test_d5_rejects_statement_with_reordered_modules() -> None:
    """声明里的模块摘要按另一种顺序算 —— CMI 对顺序敏感，必须拒。"""
    r = shared()
    par = _par_fields(r)
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in par["PA"]["modules"]]
    par["D4Statement"] = A.d4_statement(
        ap_hsm=r.p.ap, application_id=APP_ID, record_id=REC_ID,
        owner=r.verified.statement["owner"], user_sign_pk=r.verified.statement["userSignPk"],
        af=r.verified.cred.af.af, cmi=r.verified.cmi, domain2=par["domain2"],
        modules=list(reversed(mods)), phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    _raises(v1.ProtocolError, lambda: _accept(r, _reseal_par(r, par)), "modulesDigest")


def test_d5_rejects_statement_bound_to_another_credential() -> None:
    """声明的 AFRef 指向别人的 AF —— 不是这份凭证的声明。"""
    r = shared()
    par = _par_fields(r)
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in par["PA"]["modules"]]
    par["D4Statement"] = A.d4_statement(
        ap_hsm=r.p.ap, application_id=APP_ID, record_id=REC_ID,
        owner=r.verified.statement["owner"], user_sign_pk=r.verified.statement["userSignPk"],
        af=r.verified.cred.af.af + 1, cmi=r.verified.cmi, domain2=par["domain2"],
        modules=mods, phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    _raises(v1.ProtocolError, lambda: _accept(r, _reseal_par(r, par)), "afRef")


def test_didgr_requires_verified_statement() -> None:
    """没有已验签声明的 VerifiedPA 构不出 DIDGR。"""
    import dataclasses
    r = shared()
    bare = dataclasses.replace(r.verified, statement={})
    _raises(v1.ProtocolError, lambda: U.d5_build_didgr(
        user_hsm=r.p.user, verified=bare, tp_enc_pk=r.p.tp.enc_pub(),
        request_id="didgr-bare", expires=EXP), "D4Statement")


# ---------------------------------------------------------------------------
# D6：这是旧漏洞的闭环
# ---------------------------------------------------------------------------


def test_d6_rejects_domain2_substitution_in_didgr() -> None:
    """★ 旧漏洞：用户改 DIDGR 的 domain2，把 DID 签到别的 AP 域名下。

    用户对改过的 body 重新签名 —— 用户签名验得过，但与 AP 签名的声明不一致。
    """
    r = shared()
    body = {"RF": format(r.verified.rf, "x"), "domain2": "evil.example",
            "PHC": r.verified.phc1, "D4Statement": r.verified.statement,
            "requestId": "didgr-swap", "expires": EXP,
            "userSignPk": v1.pk_hex(r.p.user.pubkey())}
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: _finalize(r, box), "domain2")


def test_d6_rejects_didgr_without_statement() -> None:
    """不带声明的 DIDGR（旧格式）—— D6 不再接受。"""
    r = shared()
    body = {"RF": format(r.verified.rf, "x"), "domain2": r.verified.domain2,
            "PHC": r.verified.phc1, "requestId": "didgr-old", "expires": EXP,
            "userSignPk": v1.pk_hex(r.p.user.pubkey())}
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: _finalize(r, box), "缺字段")


def test_d6_rejects_statement_forged_with_own_ap_key() -> None:
    """用户自己造 AP 域 HSM 签一份"域名随我"的声明 —— 公钥对不上 AP。"""
    r = shared()
    rogue = v1.make_demo_hsm(domain="AP")
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in r.verified.pa["modules"]]
    forged = A.d4_statement(
        ap_hsm=rogue, application_id=APP_ID, record_id=REC_ID,
        owner=r.verified.statement["owner"], user_sign_pk=r.verified.statement["userSignPk"],
        af=r.verified.cred.af.af, cmi=r.verified.cmi, domain2="evil.example",
        modules=mods, phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    body = {"RF": format(r.verified.rf, "x"), "domain2": "evil.example",
            "PHC": r.verified.phc1, "D4Statement": forged,
            "requestId": "didgr-forged", "expires": EXP,
            "userSignPk": v1.pk_hex(r.p.user.pubkey())}
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: _finalize(r, box), "AP D4 声明")


def test_d6_rejects_statement_from_another_application() -> None:
    """拿这份合法声明去 finalize 另一张申请 —— applicationId 对不上。"""
    r = shared()
    _raises(v1.ProtocolError, lambda: _finalize(r, r.didgr, app_id="app-other"),
            "不是针对本张申请")


def test_d6_rejects_statement_bound_to_another_record() -> None:
    """声明的 AFRef 与这条 G3 记录的 AF 不符 —— 换不到别人的凭证上。"""
    r = shared()
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in r.verified.pa["modules"]]
    wrong = A.d4_statement(
        ap_hsm=r.p.ap, application_id=APP_ID, record_id=REC_ID,
        owner=r.verified.statement["owner"], user_sign_pk=r.verified.statement["userSignPk"],
        af=r.verified.cred.af.af + 1, cmi=r.verified.cmi, domain2=r.verified.domain2,
        modules=mods, phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    body = {"RF": format(r.verified.rf, "x"), "domain2": r.verified.domain2,
            "PHC": r.verified.phc1, "D4Statement": wrong,
            "requestId": "didgr-wrong-af", "expires": EXP,
            "userSignPk": v1.pk_hex(r.p.user.pubkey())}
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: _finalize(r, box), "AF")


def test_d6_rejects_statement_with_mismatched_cmi() -> None:
    """声明的 CMI 与 PHC' 里经 AP 算法1 写入的 CMI 不一致。"""
    r = shared()
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in r.verified.pa["modules"]]
    wrong = A.d4_statement(
        ap_hsm=r.p.ap, application_id=APP_ID, record_id=REC_ID,
        owner=r.verified.statement["owner"], user_sign_pk=r.verified.statement["userSignPk"],
        af=r.verified.cred.af.af, cmi="ff" * 32, domain2=r.verified.domain2,
        modules=mods, phc1_digest=r.verified.statement["phcDigest"], now=NOW)
    body = {"RF": format(r.verified.rf, "x"), "domain2": r.verified.domain2,
            "PHC": r.verified.phc1, "D4Statement": wrong,
            "requestId": "didgr-wrong-cmi", "expires": EXP,
            "userSignPk": v1.pk_hex(r.p.user.pubkey())}
    body["sig"] = sign(r.p.user, "DIDGR", json_digest(body))
    box = seal(r.p.tp.enc_pub(), body, tag="DIDGR")
    _raises(v1.ProtocolError, lambda: _finalize(r, box), "CMI")


def test_d6_records_consumed_statement_record_id() -> None:
    """成功的 D6 要记下用掉的 recordId —— 服务层据此做一次性消费。"""
    r = shared()
    _, rec2 = _finalize(r, r.didgr)
    assert rec2.d4_record_id == REC_ID
    assert rec2.did.endswith(":ap.example")


def test_d6_binds_did_to_statement_domain_not_user_claim() -> None:
    """DID 里的 AP 域名来自声明。改 DIDGR 改不动它（上面已拒），这里确认正向结果。"""
    r = shared()
    _, rec2 = _finalize(r, r.didgr)
    assert rec2.did.split(":")[4] == r.verified.statement["domain2"]
