"""用户（钱包）一侧：G1 / G4 / D1 / D3 / D5 / D6 收件。

用户持有一个 domain="USER" 的 V1SoftHSM：签名私钥与解密私钥都在里面。
每个函数只返回"下一步要发出去的密文"与"本地要存的状态"，不做任何 I/O。

errata E14：说明书的 CR 只签 r_bind，签名可被原样挪到另一份请求里。
这里所有用户签名都覆盖整份请求的关键字段 + request_id + 有效期。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import cch
from .engine import AfState, commit_af, hcgen, verify_public
from .params import Q, rand_exp
from .pke import seal
from .proto_ap import check_d4_statement, modules_digest
from .schema import af_ref, from_jsonld
from .wire import (
    ProtocolError, check_sig, hid_of, json_digest, owner_of, phc_digest, pk_hex, sign,
    unb64u,
)


def _require_user(hsm) -> None:
    if getattr(hsm, "domain", None) != "USER":
        raise PermissionError("钱包动作只能用 USER 域的 HSM")


@dataclass(frozen=True)
class PendingCR:
    hid: int
    af: AfState
    tp_nonce: str
    ap_nonce: str
    request_id: str


@dataclass(frozen=True)
class WalletCred:
    """G4 通过后用户保存的东西。"""
    hid: int
    phc: dict
    tpac: dict
    af: AfState


# ---------------------------------------------------------------------------
# G1
# ---------------------------------------------------------------------------


def g1_build_cr(*, user_hsm, pii: dict, bi: dict, tp_enc_pk: int, tp_slot: tuple[str, int],
                ap_slot: tuple[str, int], ap_sign_pk, request_id: str,
                expires: str, identity_evidence: dict | None = None) -> tuple[dict, PendingCR]:
    """式 3 + 式 4。tp_slot / ap_slot 是事先向 TP、AP 取到的 (nonce, 陷门公钥)。"""
    _require_user(user_hsm)
    hid = hid_of(pii.get("ID", ""))
    (tp_nonce, t_pub), (ap_nonce, a_pub) = tp_slot, ap_slot
    af = commit_af(hid=hid, a_pub=a_pub, t_pub=t_pub, r=rand_exp())
    body = {
        "AF": format(af.af, "x"), "rBind": format(af.r, "x"),
        "APpk": pk_hex(ap_sign_pk), "Apub": format(a_pub, "x"), "Tpub": format(t_pub, "x"),
        "tpNonce": tp_nonce, "apNonce": ap_nonce,
        "BI": bi, "PII": pii,
        "userSignPk": pk_hex(user_hsm.pubkey()), "userEncPk": format(user_hsm.enc_pub(), "x"),
        "requestId": request_id, "expires": expires,
    }
    if identity_evidence is not None:
        body["identityEvidence"] = identity_evidence
    body["sig"] = sign(user_hsm, "CR", json_digest(body))     # 签的是不含 sig 的 body
    return seal(tp_enc_pk, body, tag="CR"), PendingCR(hid, af, tp_nonce, ap_nonce, request_id)


# ---------------------------------------------------------------------------
# G4
# ---------------------------------------------------------------------------


def g4_accept_rr(*, user_hsm, rr_box: dict, pending: PendingCR, tp_sign_pk,
                 ap_sign_pk) -> WalletCred:
    _require_user(user_hsm)
    rr = user_hsm.pke_open(rr_box, tag="RR")
    phc = from_jsonld(rr["PHC"])
    errs = verify_public(phc, tp_pk=tp_sign_pk, ap_pk=ap_sign_pk)
    if errs:
        raise ProtocolError("PHC 校验未通过：" + "；".join(errs))

    tpac = rr["TPAC"]
    body = tpac["body"]
    check_sig(tp_sign_pk, tpac["sig"], "TPAC", json_digest(body), what="TPAC")
    if body["phcDigest"] != phc_digest(phc):
        raise ProtocolError("TPAC 不是为这份 PHC 签发的")
    if body["owner"] != owner_of(user_hsm.pubkey()):
        raise ProtocolError("TPAC 的归属人不是本钱包")
    if int(body["AF"], 16) != pending.af.af or phc.tpm.af != pending.af.af:
        raise ProtocolError("TP 返回的 AF 与 G1 提交的不一致")
    if (body["tpNonce"], body["apNonce"]) != (pending.tp_nonce, pending.ap_nonce):
        raise ProtocolError("TPAC 里的槽位与 G1 提交的不一致")

    # G4：AF =? h(ID)·A·T^X(IRF)·g^r'
    af = AfState(af=pending.af.af, a_pub=pending.af.a_pub, t_pub=pending.af.t_pub,
                 x_a=pending.af.x_a, x_t=cch.exponent_of("IRF", int(body["IRF"], 16)),
                 r=int(body["rBind1"], 16) % Q)
    if not af.holds(pending.hid):
        raise ProtocolError("G4：AF 与 IRF / r_bind' 的绑定关系不成立")
    return WalletCred(hid=pending.hid, phc=rr["PHC"], tpac=tpac, af=af)


# ---------------------------------------------------------------------------
# D1 / D3
# ---------------------------------------------------------------------------


def d1_build_ar(*, user_hsm, cred: WalletCred, ap_enc_pk: int, request_id: str,
                expires: str) -> dict:
    """AR = EN_pk_ap(PHC, H(ID), TPAC)。IRF 已在 TPAC 里（说明书 D1 的 IRF 不再单列）。"""
    _require_user(user_hsm)
    body = {"PHC": cred.phc, "HID": format(cred.hid, "x"), "TPAC": cred.tpac,
            "requestId": request_id, "expires": expires}
    body["sig"] = sign(user_hsm, "AR", json_digest(body))
    return seal(ap_enc_pk, body, tag="AR")


def d3_open_cmm(*, user_hsm, cmm_box: dict) -> dict:
    _require_user(user_hsm)
    return user_hsm.pke_open(cmm_box, tag="CMM")


def d3_build_paci(*, user_hsm, ap_enc_pk: int, cmm_version: str,
                  selection: list[dict], request_id: str) -> dict:
    """PACI = EN_pk_ap((CM_i, j_i))。绑定用户看到的 CMM 版本，防"确认 A、执行 B"。"""
    _require_user(user_hsm)
    body = {"cmmVersion": cmm_version, "selection": selection, "requestId": request_id}
    body["sig"] = sign(user_hsm, "PACI", json_digest(body))
    return seal(ap_enc_pk, body, tag="PACI")


# ---------------------------------------------------------------------------
# D5
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedPA:
    cred: WalletCred          # af 已更新到 D4 之后
    phc1: dict                # PHC'
    rf: int
    domain2: str
    pa: dict
    cmi: str
    statement: dict = field(default_factory=dict)   # 已验签的 D4Statement（含 sig）


def d5_accept_par(*, user_hsm, par_box: dict, cred: WalletCred, tp_sign_pk,
                  ap_sign_pk, application_id: str = "") -> VerifiedPA:
    """D5：验 PHC'、重算 CMI、验 AF 开口，并验 AP 的 D4Statement 与 PAR 内容逐项一致。

    ★ 用户确认的对象是"已验签的声明"，不是服务端随口给的一组字段：
      声明里的 domain2 / CMI / 模块摘要与 PAR 解出来的事实对不上就拒绝，
      之后 DIDGR 的用户签名会覆盖这份声明，D6 才有东西可比。
    """
    _require_user(user_hsm)
    par = user_hsm.pke_open(par_box, tag="PAR")
    phc1 = from_jsonld(par["PHC"])

    errs = verify_public(phc1, tp_pk=tp_sign_pk, ap_pk=ap_sign_pk)
    if errs:
        raise ProtocolError("PHC' 校验未通过：" + "；".join(errs))
    old = from_jsonld(cred.phc)
    if (phc1.tpm, phc1.tpproof, phc1.tpch, phc1.chproof) != (old.tpm, old.tpproof, old.tpch, old.chproof):
        raise ProtocolError("AP 改动了 TP 管理的字段")

    # 式 8：用户用 PA 里的模块自己重算 CMI
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in par["PA"]["modules"]]
    cmi = hcgen(mods, cred.hid)
    if cmi != phc1.apm.cmi:
        raise ProtocolError("D5：重算的 CMI 与 PHC 中的 CMI 不一致")
    if phc1.apm.af_ref != af_ref(cred.af.af):
        raise ProtocolError("APM.AFRef 不是本凭证的 AF")

    af = AfState(af=cred.af.af, a_pub=cred.af.a_pub, t_pub=cred.af.t_pub,
                 x_a=cch.exponent_of("CMI", cmi), x_t=cred.af.x_t,
                 r=int(par["rBind2"], 16) % Q)
    if not af.holds(cred.hid):
        raise ProtocolError("D5：AF 与 CMI / r_bind'' 的绑定关系不成立")

    statement = par.get("D4Statement") or {}
    body = check_d4_statement(statement, ap_sign_pk=ap_sign_pk)
    expected = {
        "owner": owner_of(user_hsm.pubkey()),
        "userSignPk": pk_hex(user_hsm.pubkey()),
        "afRef": af_ref(cred.af.af),
        "cmi": cmi,
        "domain2": par["domain2"],
        "modulesDigest": modules_digest(mods),
        "phcDigest": phc_digest(phc1),
    }
    for key, want in expected.items():
        if body[key] != want:
            raise ProtocolError(f"D5：D4Statement 的 {key} 与 PAR 实际内容不一致")
    if application_id and body["applicationId"] != application_id:
        raise ProtocolError("D5：D4Statement 不是针对本次申请签发的")

    new_cred = WalletCred(hid=cred.hid, phc=par["PHC"], tpac=cred.tpac, af=af)
    return VerifiedPA(cred=new_cred, phc1=par["PHC"], rf=int(par["RF"], 16),
                      domain2=par["domain2"], pa=par["PA"], cmi=cmi, statement=statement)


def d5_build_didgr(*, user_hsm, verified: VerifiedPA, tp_enc_pk: int, request_id: str,
                   expires: str) -> dict:
    """DIDGR = EN_pk_tp(RF, domain2, PHC', D4Statement)。用户签名 = "我已核验 D5"的回执。

    声明整份进 body，用户签名覆盖它（json_digest 覆盖全 body）——
    D6 由此同时拿到 AP 的签名和用户对同一份声明的确认。
    """
    _require_user(user_hsm)
    if not verified.statement:
        raise ProtocolError("D5 未取得已验签的 D4Statement，不能构造 DIDGR")
    body = {"RF": format(verified.rf, "x"), "domain2": verified.domain2,
            "PHC": verified.phc1, "D4Statement": verified.statement,
            "requestId": request_id, "expires": expires,
            "userSignPk": pk_hex(user_hsm.pubkey())}
    body["sig"] = sign(user_hsm, "DIDGR", json_digest(body))
    return seal(tp_enc_pk, body, tag="DIDGR")


# ---------------------------------------------------------------------------
# D6 收件
# ---------------------------------------------------------------------------


def d6_accept_final(*, user_hsm, final_box: dict, verified: VerifiedPA, tp_sign_pk,
                    ap_sign_pk) -> tuple[str, dict]:
    """返回 (DID, PHC'')。DID 从 CDID 里用自己的私钥解出 —— PHC 里只有密文形态。"""
    _require_user(user_hsm)
    fin = user_hsm.pke_open(final_box, tag="FINAL")
    phc2 = from_jsonld(fin["PHC"])
    errs = verify_public(phc2, tp_pk=tp_sign_pk, ap_pk=ap_sign_pk)
    if errs:
        raise ProtocolError("PHC'' 校验未通过：" + "；".join(errs))
    prev = from_jsonld(verified.phc1)
    if (phc2.apm, phc2.approof, phc2.tpm.af) != (prev.apm, prev.approof, prev.tpm.af):
        raise ProtocolError("TP 在 D6 改动了 AP 管理的字段或 AF")
    did = user_hsm.pke_open(unb64u(phc2.tpm.cdid), tag="CDID")["DID"]
    if not did.endswith(":" + verified.domain2):
        raise ProtocolError("DID 里的 AP 域名与 D4 分配的不一致")
    return did, fin["PHC"]


__all__ = ["PendingCR", "WalletCred", "VerifiedPA", "g1_build_cr", "g4_accept_rr",
           "d1_build_ar", "d3_open_cmm", "d3_build_paci", "d5_accept_par",
           "d5_build_didgr", "d6_accept_final"]
