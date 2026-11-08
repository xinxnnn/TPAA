"""AP 一侧：D2 / D2' CMM / D4、R1 协作。

★ AP 能拿到的东西：PHC、H(ID)、TPAC（含 EN_pk_ap(r_ap)），**拿不到 BI / PII**。
★ r_ap'（算法1 后的 APCH 开口）只存在 AP 记录里，永不外发 —— 否则 TP 手里的 r_ap
  与它构成两组开口，K1 重现（errata 限界 2）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import cch
from .engine import AfState, algorithm1, hcgen, rebind_af, verify_public
from .params import Q
from .pke import seal
from .schema import af_ref, from_jsonld, to_jsonld
from .supervision import compute_rf, compute_s_ap
from .wire import (
    ProtocolError, check_sig, json_digest, not_expired, owner_of, phc_digest, pk_from_hex,
    sign,
)


def _require_ap(hsm) -> None:
    if getattr(hsm, "domain", None) != "AP":
        raise PermissionError("该动作只能由 AP 的 HSM 执行")


def _unsigned(body: dict) -> dict:
    return {k: v for k, v in body.items() if k != "sig"}


@dataclass(frozen=True)
class ApSession:
    hid: int
    phc: dict
    tpac: dict
    af: AfState
    r_ap: int
    owner: str
    user_sign_pk: str
    user_enc_pk: int
    request_id: str


def ap_open_ar(*, ap_hsm, ar_box: dict, tp_sign_pk, now: str) -> ApSession:
    """D2：解 AR → 验 TPAC → 验用户签名（公钥来自 TPAC，即 TP 认证过的那把）→ 验 AF。"""
    _require_ap(ap_hsm)
    ar = ap_hsm.pke_open(ar_box, tag="AR")
    tpac = ar["TPAC"]
    body = tpac["body"]
    check_sig(tp_sign_pk, tpac["sig"], "TPAC", json_digest(body), what="TPAC")
    check_sig(pk_from_hex(body["userSignPk"]), ar["sig"], "AR", json_digest(_unsigned(ar)),
              what="AR 用户")
    not_expired(ar["expires"], now, "AR")

    phc = from_jsonld(ar["PHC"])
    errs = verify_public(phc, tp_pk=tp_sign_pk, ap_pk=ap_hsm.pubkey())
    if errs:
        raise ProtocolError("PHC 校验未通过：" + "；".join(errs))
    if body["phcDigest"] != phc_digest(phc) or int(body["AF"], 16) != phc.tpm.af:
        raise ProtocolError("TPAC 不是为这份 PHC 签发的")
    if body["owner"] != owner_of(pk_from_hex(body["userSignPk"])):
        raise ProtocolError("TPAC 的归属人与其中的用户公钥不对应")
    if ap_hsm.slot_public(body["apNonce"]) != int(body["Apub"], 16):
        raise ProtocolError("TPAC 里的 A 不是本 AP 为该槽位分配的陷门公钥")

    hid = int(ar["HID"], 16)
    af = AfState(af=phc.tpm.af, a_pub=int(body["Apub"], 16), t_pub=int(body["Tpub"], 16),
                 x_a=cch.INITIAL_EXPONENT, x_t=cch.exponent_of("IRF", int(body["IRF"], 16)),
                 r=int(body["rBind1"], 16) % Q)
    if not af.holds(hid):           # D2：H(ID)·pk_ap·pk_tp^IRF·g^r' =? AF
        raise ProtocolError("D2：AF 与 H(ID) / IRF / r_bind' 不符")
    r_ap = int(ap_hsm.pke_open(body["encRap"], tag="RAP")["rAp"], 16)
    return ApSession(hid=hid, phc=ar["PHC"], tpac=tpac, af=af, r_ap=r_ap,
                     owner=body["owner"], user_sign_pk=body["userSignPk"],
                     user_enc_pk=int(body["userEncPk"], 16), request_id=ar["requestId"])


def ap_send_cmm(*, session: ApSession, cmm: dict) -> dict:
    """D2 末：EN_pk_a(CMM)。cmm 至少含 version 与 categories。"""
    if "version" not in cmm:
        raise ProtocolError("CMM 必须带版本号（D3 要绑定它）")
    return seal(session.user_enc_pk, cmm, tag="CMM")


@dataclass(frozen=True)
class ApRecord:
    """D4 "本地数据库"：H(ID) → {r_bind'', r_ap', CMC, CMI, IRF}。"""
    hid: int
    af: AfState
    r_ap: int
    cmi: str
    modules: list
    irf: int
    rf: int
    domain2: str
    owner: str
    statement: dict = field(default_factory=dict)   # D4Statement（AP 签名），D6 据此绑定


STATEMENT_VERSION = "tpaa-v1-d4-statement"
STATEMENT_FIELDS = ("version", "applicationId", "recordId", "owner", "userSignPk",
                    "afRef", "cmi", "domain2", "modulesDigest", "phcDigest", "issuedAt")


def modules_digest(modules) -> str:
    """有序模块清单的摘要。顺序进摘要 —— 换序就是换配置（式 8 对顺序敏感）。"""
    return json_digest([{"moduleId": m, "version": v, "digest": d} for m, v, d in modules])


def d4_statement(*, ap_hsm, application_id: str, record_id: str, owner: str, user_sign_pk: str,
                 af: int, cmi: str, domain2: str, modules, phc1_digest: str,
                 now: str) -> dict:
    """D4Statement：把"这套配置、这个域名、这个人"钉在 AP 的签名下。

    ★ 为什么必须有它：D6 以前从用户递来的 DIDGR 里直接取 domain2，
      AP 实际分配了什么无从对证 —— 用户（或被控的门户）改一个字段，
      TP 就会把 DID 签到另一个 AP 域名下。
    ★ 声明进 PAR（对用户加密），D5 验签后由用户签名覆盖，D6 只认声明里的 domain2/CMI。
    """
    _require_ap(ap_hsm)
    if not application_id or not record_id:
        raise ProtocolError("D4Statement 必须绑定 applicationId 与 recordId")
    body = {
        "version": STATEMENT_VERSION,
        "applicationId": application_id, "recordId": record_id,
        "owner": owner, "userSignPk": user_sign_pk,
        "afRef": af_ref(af), "cmi": cmi, "domain2": domain2,
        "modulesDigest": modules_digest(modules), "phcDigest": phc1_digest,
        "issuedAt": now,
    }
    body["sig"] = sign(ap_hsm, "D4Statement", json_digest(body))
    return body


def check_d4_statement(statement: dict, *, ap_sign_pk) -> dict:
    """验 AP 签名并检查字段齐备；返回不含 sig 的 body（调用方再逐项比对自己的事实）。"""
    body = _unsigned(statement or {})
    missing = [f for f in STATEMENT_FIELDS if not body.get(f)]
    if missing:
        raise ProtocolError("D4Statement 缺字段：" + "、".join(missing))
    if body["version"] != STATEMENT_VERSION:
        raise ProtocolError(f"D4Statement 版本不认识：{body['version']!r}")
    check_sig(ap_sign_pk, (statement or {}).get("sig", ""), "D4Statement", json_digest(body),
              what="AP D4 声明")
    return body


def ap_build(*, ap_hsm, session: ApSession, paci_box: dict, cmm_version: str,
             resolve, sup_pub, domain2: str, now: str, application_id: str,
             record_id: str) -> tuple[dict, ApRecord]:
    """D4。resolve(selection) → [(module_id, version, digest)]：模块仓库查表，摘要取自仓库。

    application_id / record_id 进 D4Statement：recordId 由 AP 先定号再签，
    让 D6 能把"这份声明"一次性消费掉，不能换到另一张申请上去用。
    """
    _require_ap(ap_hsm)
    paci = ap_hsm.pke_open(paci_box, tag="PACI")
    check_sig(pk_from_hex(session.user_sign_pk), paci["sig"], "PACI",
              json_digest(_unsigned(paci)), what="PACI 用户")
    if paci["cmmVersion"] != cmm_version:
        raise ProtocolError("用户确认的 CMM 版本与当前目录不一致")
    modules = resolve(paci["selection"])
    cmi = hcgen(modules, session.hid)                                       # 式 8

    phc1, r_ap1 = algorithm1(from_jsonld(session.phc), ap_hsm=ap_hsm, r_ap=session.r_ap,
                             cmi=cmi, time=now)                             # 算法1
    af2 = rebind_af(session.af, hsm=ap_hsm, hid=session.hid,
                    nonce=session.tpac["body"]["apNonce"], owner=session.owner,
                    kind="CMI", value=cmi)                                  # 算法1 第 11–13 行
    irf = int(session.tpac["body"]["IRF"], 16)
    rf = compute_rf(irf, compute_s_ap(ap_hsm, af2.af), sup_pub)             # 式 9

    pa = {"modules": [{"moduleId": m, "version": v, "digest": d} for m, v, d in modules]}
    statement = d4_statement(
        ap_hsm=ap_hsm, application_id=application_id, record_id=record_id,
        owner=session.owner, user_sign_pk=session.user_sign_pk, af=af2.af, cmi=cmi,
        domain2=domain2, modules=modules, phc1_digest=phc_digest(phc1), now=now)
    par = seal(session.user_enc_pk, {"rBind2": format(af2.r, "x"), "RF": format(rf, "x"),
                                     "domain2": domain2, "PHC": to_jsonld(phc1), "PA": pa,
                                     "D4Statement": statement},
               tag="PAR")
    rec = ApRecord(hid=session.hid, af=af2, r_ap=r_ap1, cmi=cmi, modules=list(modules),
                   irf=irf, rf=rf, domain2=domain2, owner=session.owner, statement=statement)
    return par, rec


def ap_assist(*, ap_hsm, af: int, case_ok: bool) -> int:
    """R1：AP 同意协查后交回 s_ap。是否同意由协查服务判断（立案、用途、有效期）。"""
    _require_ap(ap_hsm)
    if not case_ok:
        raise ProtocolError("未获授权的协查请求")
    return compute_s_ap(ap_hsm, af)


__all__ = ["ApSession", "ApRecord", "ap_open_ar", "ap_send_cmm", "ap_build", "ap_assist",
           "d4_statement", "check_d4_statement", "modules_digest", "STATEMENT_VERSION",
           "STATEMENT_FIELDS"]
