"""R1 跨域协查的授权与应答（errata E18）。

原文 R1 只写"TP 向 AP 请求、AP 同意后返回 s_ap"，没有说 AP 凭什么同意。
proto0 里 AP 收到的是一个 `case_ok: bool` —— 也就是 TP 说了算，"联合揭露"退化成 TP 单方。

v1 的规则：
    立案   两名**不同**监管员各用自己的 STAFF 密钥签 encode("CASE/approve", caseId, DID, purpose)
    请求   TP 签 encode("CASE/assist", requestId, caseId, DID, H(AF), purpose, expires, 两份签名的摘要)
    AP 验  TP 签名 + 至少两名不同监管员（**AP 自己配置的名录**）的签名 + 未过期 + AF 确属本 AP 签发
    应答   s_ap 用 TP 的加密公钥封装（tag = ASSIST），绑定 requestId —— 不以明文过线

★ AP 用的是**自己的**监管员名录。TP 在自己库里加一个"监管员"，AP 不认。
  "联合"在这里落成了：AP 只有在看到它信任的两个人签了字时才交出 s_ap。
"""

from __future__ import annotations

from .encoding import digest
from .pke import seal
from .wire import ProtocolError, check_sig, json_digest, not_expired, pk_from_hex, pk_hex, sign

ASSIST_TAG = "ASSIST"
FORENSIC_TAG = "FORENSIC"
MIN_APPROVERS = 2


def _af_ref(af: int) -> str:
    return digest("CASE/af", af).hex()


def sign_case_approval(staff_hsm, *, case_id: str, did: str, purpose: str) -> dict:
    """监管员在自己的终端上调用：私钥不进服务。"""
    if getattr(staff_hsm, "domain", None) != "STAFF":
        raise PermissionError("立案签字必须用监管员个人的 STAFF 密钥")
    return {"signPk": pk_hex(staff_hsm.pubkey()),
            "sig": sign(staff_hsm, "CASE/approve", case_id, did, purpose)}


def check_case_approval(appr: dict, *, case_id: str, did: str, purpose: str) -> None:
    check_sig(pk_from_hex(appr["signPk"]), appr["sig"], "CASE/approve", case_id, did, purpose,
              what="立案签字")


def build_assist_request(tp_hsm, *, request_id: str, case_id: str, did: str, af: int,
                         purpose: str, approvals: list[dict], expires: str) -> dict:
    if getattr(tp_hsm, "domain", None) != "TP":
        raise PermissionError("协查请求只能由 TP 发出")
    body = {"requestId": request_id, "caseId": case_id, "did": did, "afRef": _af_ref(af),
            "af": format(af, "x"), "purpose": purpose, "expires": expires,
            "approvals": approvals}
    body["tpSig"] = sign(tp_hsm, "CASE/assist", json_digest(body))
    return body


def ap_check_assist(req: dict, *, tp_sign_pk, supervisors: set[str], now: str) -> int:
    """AP 侧：校验协查请求，返回 AF。不通过一律抛 ProtocolError。

    supervisors：AP 自己配置的监管员签名公钥（hex）集合。
    """
    body = {k: v for k, v in req.items() if k != "tpSig"}
    check_sig(tp_sign_pk, req.get("tpSig", ""), "CASE/assist", json_digest(body), what="TP 协查请求")
    not_expired(req["expires"], now, "协查请求")
    af = int(req["af"], 16)
    if req["afRef"] != _af_ref(af):
        raise ProtocolError("协查请求的 afRef 与 af 不一致")
    seen = set()
    for appr in req.get("approvals", []):
        if appr["signPk"] not in supervisors:
            continue                                  # 不在 AP 名录里的签字不算数
        check_case_approval(appr, case_id=req["caseId"], did=req["did"], purpose=req["purpose"])
        seen.add(appr["signPk"])
    if len(seen) < MIN_APPROVERS:
        raise ProtocolError(
            f"协查需要至少 {MIN_APPROVERS} 名 AP 认可的监管员签字，实际有效 {len(seen)} 名")
    return af


def ap_seal_answer(*, tp_enc_pk: int, request_id: str, s_ap: int) -> dict:
    return seal(tp_enc_pk, {"requestId": request_id, "sAp": format(s_ap, "x")}, tag=ASSIST_TAG)


def tp_open_answer(tp_hsm, box: dict, *, request_id: str) -> int:
    ans = tp_hsm.pke_open(box, tag=ASSIST_TAG)
    if ans.get("requestId") != request_id:
        raise ProtocolError("协查应答不是对这次请求的")
    return int(ans["sAp"], 16)


def seal_forensic(*, recipient_enc_pk: int, case_id: str, bundle: dict) -> dict:
    """取证包只封给指定的监管员；接口与库里都只见密文。"""
    return seal(recipient_enc_pk, {"caseId": case_id, **bundle}, tag=FORENSIC_TAG)


def open_forensic(staff_hsm, box: dict) -> dict:
    return staff_hsm.pke_open(box, tag=FORENSIC_TAG)


__all__ = ["sign_case_approval", "check_case_approval", "build_assist_request",
           "ap_check_assist", "ap_seal_answer", "tp_open_answer", "seal_forensic",
           "open_forensic", "MIN_APPROVERS"]
