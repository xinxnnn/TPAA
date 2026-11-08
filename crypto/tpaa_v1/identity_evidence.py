"""Signed evidence that an independent verifier checked the physical person.

The evidence is carried *inside* the encrypted CR.  It binds a verification
decision to one wallet key, TP slot and request, without placing PII in the
attestation.  A signature proves who made the decision; it does not perform
document or biometric verification on its own.
"""

from __future__ import annotations

from datetime import datetime

from .wire import ProtocolError, check_sig, json_digest, pk_from_hex, sign

VERSION = "tpaa-v1-identity-evidence"
LEVELS = {"basic": 1, "substantial": 2, "high": 3}
FIELDS = frozenset({
    "version", "issuer", "result", "subjectHid", "userSignPk", "tpNonce",
    "requestId", "method", "assuranceLevel", "evidenceRef", "issuedAt", "expiresAt",
})


def issue(*, verifier_hsm, issuer: str, hid: int, user_sign_pk: str,
          tp_nonce: str, request_id: str, method: str, assurance_level: str,
          evidence_ref: str, issued_at: str, expires_at: str) -> dict:
    """Reference issuer for tests and verifier adapters; never self-issue in TP."""
    body = {
        "version": VERSION, "issuer": issuer, "result": "verified",
        "subjectHid": format(hid, "x"), "userSignPk": user_sign_pk,
        "tpNonce": tp_nonce, "requestId": request_id, "method": method,
        "assuranceLevel": assurance_level, "evidenceRef": evidence_ref,
        "issuedAt": issued_at, "expiresAt": expires_at,
    }
    _shape(body)
    return {"body": body, "sig": sign(verifier_hsm, "IdentityEvidence", json_digest(body))}


def verify(evidence: dict, *, trusted_issuers: dict[str, str], min_assurance: str,
           hid: int, user_sign_pk: str, tp_nonce: str, request_id: str,
           now: str) -> dict:
    """Validate signature, trust, freshness and binding to the signed CR."""
    if not isinstance(evidence, dict) or set(evidence) != {"body", "sig"}:
        raise ProtocolError("缺少身份核验证据或证据结构不合法")
    body = evidence["body"]
    _shape(body)
    if body["version"] != VERSION or body["result"] != "verified":
        raise ProtocolError("身份核验证据版本或结论不正确")
    issuer_pk = trusted_issuers.get(body["issuer"])
    if not issuer_pk:
        raise ProtocolError("身份核验签发方不在信任名录中")
    try:
        pk = pk_from_hex(issuer_pk)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("身份核验签发方公钥配置无效") from exc
    check_sig(pk, evidence["sig"], "IdentityEvidence", json_digest(body),
              what="身份核验证据")
    if LEVELS[body["assuranceLevel"]] < LEVELS.get(min_assurance, 99):
        raise ProtocolError("身份核验保证级别不足")
    if not body["issuedAt"] <= now < body["expiresAt"]:
        raise ProtocolError("身份核验证据尚未生效或已过期")
    expected = {"subjectHid": format(hid, "x"), "userSignPk": user_sign_pk,
                "tpNonce": tp_nonce, "requestId": request_id}
    for key, value in expected.items():
        if body[key] != value:
            raise ProtocolError(f"身份核验证据的 {key} 与 CR 不一致")
    return body


def _shape(body: dict) -> None:
    if not isinstance(body, dict) or set(body) != FIELDS:
        raise ProtocolError("身份核验证据字段不完整或含未知字段")
    if any(not isinstance(v, str) or not v for v in body.values()):
        raise ProtocolError("身份核验证据字段必须是非空字符串")
    if body["assuranceLevel"] not in LEVELS:
        raise ProtocolError("身份核验证据保证级别不认识")
    for field in ("issuedAt", "expiresAt"):
        value = body[field]
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        except ValueError as exc:
            raise ProtocolError(f"身份核验证据的 {field} 格式不正确") from exc
        if parsed.strftime("%Y-%m-%dT%H:%M:%S") != value:
            raise ProtocolError(f"身份核验证据的 {field} 格式不正确")
    if body["expiresAt"] <= body["issuedAt"]:
        raise ProtocolError("身份核验证据有效期不正确")


__all__ = ["VERSION", "LEVELS", "issue", "verify"]
