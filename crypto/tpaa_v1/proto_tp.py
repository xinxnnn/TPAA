"""TP 一侧：G2（拆成 受理 / 审批 / 签发）、D6、R1、R2。

服务分工（P3 接入时）：
    tp_open_cr       identity-service   解开 CR、验用户签名与 AF（式 3）
    approve          review-service     人工审批只产生签名证据，**不持协议密钥**
    tp_issue         phc-service        验审批证据 → IRF → CCH → SecInfo → G3 → TPAC → RR
    tp_finalize      phc-service + did  D6：SCID / CSCID / did:wba / CDID / 算法2 / ECID 重封
    tp_open_did …    supervision        R1 / R2

★ TP 的记录（G3 "本地数据库"）：H(ID) → {ECID, r_bind', r_tp, 槽位, AF, 用户公钥}。
  这张表让 TP 能单方把 AF 关联到 H(ID) —— errata S2，原文结构使然。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

from ..hsm.v1 import SlotError
from . import cch
from .engine import AfState, algorithm2, issue_phc, rebind_af, verify_public
from .params import Q
from .pke import canonical_json, seal
from .proto_ap import check_d4_statement
from .schema import af_ref, from_jsonld, to_jsonld
from .supervision import compute_irf, ecid_mask, open_ecid, reveal_hid, seal_ecid
from .wire import (
    ProtocolError, b64u, check_sig, hid_of, json_digest, not_expired, owner_of,
    phc_digest, pk_from_hex, pk_hex, sign, unb64u,
)
from ..envelope.cipher import decrypt as etm_decrypt, encrypt as etm_encrypt


def _require_tp(hsm) -> None:
    if getattr(hsm, "domain", None) != "TP":
        raise PermissionError("该动作只能由 TP 的 HSM 执行")


def _unsigned(body: dict) -> dict:
    return {k: v for k, v in body.items() if k != "sig"}


# ---------------------------------------------------------------------------
# G2-a 受理（identity-service）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenedCR:
    hid: int
    af: AfState
    tp_nonce: str
    ap_nonce: str
    owner: str
    user_sign_pk: str
    user_enc_pk: int
    ap_sign_pk: str
    bi: dict
    pii: dict
    request_id: str
    cr_digest: str
    identity_evidence: dict | None = None


def tp_open_cr(*, tp_hsm, cr_box: dict, now: str,
               recover_missing_slot: bool = False) -> OpenedCR:
    _require_tp(tp_hsm)
    cr = tp_hsm.pke_open(cr_box, tag="CR")
    upk = pk_from_hex(cr["userSignPk"])
    check_sig(upk, cr["sig"], "CR", json_digest(_unsigned(cr)), what="CR 用户")
    not_expired(cr["expires"], now, "CR")

    hid = hid_of(cr["PII"].get("ID", ""))
    t_pub = int(cr["Tpub"], 16)
    af = AfState(af=int(cr["AF"], 16), a_pub=int(cr["Apub"], 16), t_pub=t_pub,
                 x_a=cch.INITIAL_EXPONENT, x_t=cch.INITIAL_EXPONENT,
                 r=int(cr["rBind"], 16) % Q)
    if not af.holds(hid):           # G2：AF =? H(ID)·pk_ap·pk_tp·g^r_bind
        raise ProtocolError("G2：AF 与 H(ID) / r_bind 不符")
    try:
        slot_pub = tp_hsm.slot_public(cr["tpNonce"])
    except SlotError:
        if not recover_missing_slot:
            raise
        slot_pub = tp_hsm.recover_slot(
            nonce=cr["tpNonce"], owner=owner_of(upk), af=af.af, expected_pub=t_pub)
    if slot_pub != t_pub:
        raise ProtocolError("CR 里的 T 不是本 TP 为该槽位分配的陷门公钥")
    return OpenedCR(hid=hid, af=af, tp_nonce=cr["tpNonce"], ap_nonce=cr["apNonce"],
                    owner=owner_of(upk), user_sign_pk=cr["userSignPk"],
                    user_enc_pk=int(cr["userEncPk"], 16), ap_sign_pk=cr["APpk"],
                    bi=cr["BI"], pii=cr["PII"], request_id=cr["requestId"],
                    cr_digest=json_digest(_unsigned(cr)),
                    identity_evidence=cr.get("identityEvidence"))


# ---------------------------------------------------------------------------
# 审批闸门（review-service）
# ---------------------------------------------------------------------------


def approve(*, reviewer_hsm, cr_digest: str, reviewers: list[str], expires: str) -> dict:
    """人工审批的签名证据。签名私钥属于 review-service，不是 TP 协议密钥。"""
    if len(set(reviewers)) != 1 or any(not r for r in reviewers):
        raise ProtocolError("TP 人工审批必须由一名审核员作出")
    body = {"crDigest": cr_digest, "decision": "approve", "reviewer": reviewers[0],
            "reviewers": reviewers, "expires": expires}
    return {"body": body, "sig": sign(reviewer_hsm, "Approval", json_digest(body))}


def check_approval(approval: dict, *, review_pk, cr_digest: str, now: str) -> None:
    body = approval.get("body") or {}
    check_sig(review_pk, approval.get("sig", ""), "Approval", json_digest(body), what="审批证据")
    if body.get("decision") != "approve":
        raise ProtocolError("审批结论不是通过")
    if body.get("crDigest") != cr_digest:
        raise ProtocolError("审批证据不是针对这份申请的")
    not_expired(body.get("expires", ""), now, "审批证据")


# ---------------------------------------------------------------------------
# G2-b / G3 签发（phc-service）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TpRecord:
    hid: int
    af: AfState              # TP 侧开口：x_a=1, x_t=X(IRF), r=r_bind'
    tp_nonce: str
    ap_nonce: str
    owner: str
    user_sign_pk: str
    user_enc_pk: int
    ecid: int
    r_tp: int
    irf: int
    phc_version: int
    did: str = ""
    phc_digest: str = ""
    cmi: str = ""
    d4_record_id: str = ""       # D6 消费掉的那份 D4Statement，供对账与一次性检查


def _s1(tp_hsm, af: int) -> bytes:
    """errata E16：s1 = KDF(λ1, sk_tp·AF) → TP 的 PRF(“s1”, AF)（E2：不复用 Paillier/签名私钥）。"""
    return tp_hsm.prf("s1", af).to_bytes(32, "big")


def tp_issue(*, tp_hsm, opened: OpenedCR, approval: dict, review_pk, sup_pub, storage,
             ap_ch, ap_sign_pk, ap_enc_pk: int, now: str) -> tuple[dict, TpRecord]:
    _require_tp(tp_hsm)
    check_approval(approval, review_pk=review_pk, cr_digest=opened.cr_digest, now=now)
    if pk_hex(ap_sign_pk) != opened.ap_sign_pk:
        raise ProtocolError("CR 指定的 AP 与本次签发的 AP 不一致")

    irf = compute_irf(opened.hid, sup_pub)                                   # 式 5
    af1 = rebind_af(opened.af, hsm=tp_hsm, hid=opened.hid, nonce=opened.tp_nonce,
                    owner=opened.owner, kind="IRF", value=irf)               # CCH

    s1 = _s1(tp_hsm, af1.af)                                                 # SecInfo
    nonce, ct, mac = etm_encrypt(s1, canonical_json({"BI": opened.bi, "PII": opened.pii}))
    cid = storage.put(nonce + mac + ct, requester="phc-service")
    ecid = seal_ecid(cid, sup_pub)                                           # 式 6 第一段

    issued = issue_phc(tp_hsm=tp_hsm, ap_ch=ap_ch, ap_pk=ap_sign_pk, af=af1.af,
                       ecid=format(ecid, "x"), time=now)                     # G3
    body = {                                                                 # 式 7
        "IRF": format(irf, "x"), "rBind1": format(af1.r, "x"),
        "encRap": seal(ap_enc_pk, {"rAp": format(issued.r_ap, "x")}, tag="RAP"),
        "AF": format(af1.af, "x"), "Apub": format(af1.a_pub, "x"), "Tpub": format(af1.t_pub, "x"),
        "tpNonce": opened.tp_nonce, "apNonce": opened.ap_nonce,
        "owner": opened.owner, "userSignPk": opened.user_sign_pk,
        "userEncPk": format(opened.user_enc_pk, "x"), "phcDigest": phc_digest(issued.phc),
    }
    tpac = {"body": body, "sig": sign(tp_hsm, "TPAC", json_digest(body))}
    rr = seal(opened.user_enc_pk, {"PHC": to_jsonld(issued.phc), "TPAC": tpac}, tag="RR")
    rec = TpRecord(hid=opened.hid, af=af1, tp_nonce=opened.tp_nonce, ap_nonce=opened.ap_nonce,
                   owner=opened.owner, user_sign_pk=opened.user_sign_pk,
                   user_enc_pk=opened.user_enc_pk, ecid=ecid, r_tp=issued.r_tp, irf=irf,
                   phc_version=issued.phc.version, phc_digest=phc_digest(issued.phc))
    return rr, rec


# ---------------------------------------------------------------------------
# D6（phc-service + did-service）
# ---------------------------------------------------------------------------


def reseal_ecid(ecid: int, mask: int, sup_pub) -> int:
    """式 6 第二段：同态地把 mask 加进去，不需要解开 ECID（phc-service 没有 psk）。"""
    return ecid * sup_pub.seal(mask) % (sup_pub.n * sup_pub.n)


def tp_finalize(*, tp_hsm, didgr_box: dict, rec: TpRecord, sup_pub, tp_sign_pk, ap_sign_pk,
                domain1: str, now: str, application_id: str) -> tuple[dict, TpRecord]:
    """D6。domain2 与 CMI 只从 AP 签名的 D4Statement 取，不从用户递来的字段取。

    ★ 以前这里用 `g["domain2"]` —— 那是 DIDGR 里的一个普通字段，
      用户签名能覆盖它，但"AP 到底分配了哪个域名"没有任何证据。
      现在：AP 签名的声明必须在、必须验得过、必须与本条 G3 记录对得上。
    """
    _require_tp(tp_hsm)
    g = tp_hsm.pke_open(didgr_box, tag="DIDGR")
    if g["userSignPk"] != rec.user_sign_pk:
        raise ProtocolError("DIDGR 不是该凭证的持有人发起的")
    check_sig(pk_from_hex(rec.user_sign_pk), g["sig"], "DIDGR", json_digest(_unsigned(g)),
              what="DIDGR 用户")
    not_expired(g["expires"], now, "DIDGR")

    phc1 = from_jsonld(g["PHC"])
    errs = verify_public(phc1, tp_pk=tp_sign_pk, ap_pk=ap_sign_pk)
    if errs:
        raise ProtocolError("PHC' 校验未通过：" + "；".join(errs))
    if not phc1.apm.cmi:
        raise ProtocolError("PHC' 还没有经过 AP 的算法1（APM.CMI 为空）")
    if phc1.tpm.af != rec.af.af or phc1.apm.af_ref != af_ref(rec.af.af):
        raise ProtocolError("PHC' 不是这条记录对应的凭证")

    # D4Statement：AP 签名 → 与本条记录逐项对齐 → 只认声明里的 domain2 / CMI
    st = check_d4_statement(g.get("D4Statement"), ap_sign_pk=ap_sign_pk)
    if st["applicationId"] != application_id:
        raise ProtocolError("D4Statement 不是针对本张申请签发的")
    if st["owner"] != rec.owner or st["userSignPk"] != rec.user_sign_pk:
        raise ProtocolError("D4Statement 的归属人 / 用户公钥与 G3 记录不符")
    if st["afRef"] != af_ref(rec.af.af):
        raise ProtocolError("D4Statement 绑定的不是这条记录的 AF")
    if st["cmi"] != phc1.apm.cmi:
        raise ProtocolError("D4Statement 的 CMI 与 PHC' 中的 CMI 不一致")
    if st["phcDigest"] != phc_digest(phc1):
        raise ProtocolError("D4Statement 绑定的不是这份 PHC'")
    if g.get("domain2") != st["domain2"]:
        raise ProtocolError("DIDGR 的 domain2 与 AP 签名声明中的不一致")
    domain2 = st["domain2"]

    rf = int(g["RF"], 16)
    cscid = seal(tp_hsm.enc_pub(), {"AF": format(rec.af.af, "x"), "RF": g["RF"]}, tag="CSCID")
    did = f"did:wba:{b64u(cscid)}:{domain1}:{domain2}"
    cdid = b64u(seal(rec.user_enc_pk, {"DID": did}, tag="CDID"))
    ecid1 = reseal_ecid(rec.ecid, ecid_mask(tp_hsm, rf, sup_pub.n), sup_pub)

    phc2, r_tp1 = algorithm2(phc1, tp_hsm=tp_hsm, r_tp=rec.r_tp, cdid=cdid, time=now,
                             ecid=format(ecid1, "x"))
    final = seal(rec.user_enc_pk, {"PHC": to_jsonld(phc2)}, tag="FINAL")
    return final, replace(rec, ecid=ecid1, r_tp=r_tp1, phc_version=phc2.version,
                          did=did, phc_digest=phc_digest(phc2), cmi=phc2.apm.cmi,
                          d4_record_id=st["recordId"])


# ---------------------------------------------------------------------------
# R1 / R2（supervision-service）
# ---------------------------------------------------------------------------


def tp_open_did(*, tp_hsm, did: str) -> tuple[int, int]:
    """R1 第一步：(AF, RF) = DE_sk_tp(CSCID)。"""
    _require_tp(tp_hsm)
    parts = did.split(":")
    if len(parts) != 5 or parts[:2] != ["did", "wba"]:
        raise ProtocolError(f"不是 tpaa_v1 的 did:wba 标识：{did[:40]}…")
    scid = tp_hsm.pke_open(unb64u(parts[2]), tag="CSCID")
    return int(scid["AF"], 16), int(scid["RF"], 16)


def tp_reveal(*, sup_key, rf: int, s_ap: int, rec: TpRecord) -> int:
    """R1：H(ID) = PDec(RF) − s_ap，再用 TP 自己那组开口核对 AF（AF 恒定，旧开口依然成立）。"""
    hid = reveal_hid(rf, s_ap, sup_key)
    if hid != rec.hid or not rec.af.holds(hid):
        raise ProtocolError("R1：还原出的 H(ID) 与凭证的 AF 不符（s_ap 不对，或 CSCID 被换过）")
    return hid


def tp_recover_pii(*, tp_hsm, sup_key, rec: TpRecord, rf: int, storage) -> dict:
    """R2：ECID → CID → SecInfo → (BI, PII)。"""
    _require_tp(tp_hsm)
    n = sup_key.public().n
    cid = open_ecid(rec.ecid, sup_key, mask=ecid_mask(tp_hsm, rf, n) if rec.did else 0)
    blob = storage.get(cid, requester="supervision-service")
    if blob is None:
        raise ProtocolError("IPFS 上找不到 SecInfo")
    nonce, mac, ct = blob[:16], blob[16:48], blob[48:]
    pt = etm_decrypt(_s1(tp_hsm, rec.af.af), nonce, ct, mac)
    if pt is None:
        raise ProtocolError("SecInfo 解密失败")
    return json.loads(pt)


__all__ = ["OpenedCR", "TpRecord", "tp_open_cr", "approve", "check_approval", "tp_issue",
           "reseal_ecid", "tp_finalize", "tp_open_did", "tp_reveal", "tp_recover_pii"]
