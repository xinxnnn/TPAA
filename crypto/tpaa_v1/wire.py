"""协议消息的公共件：身份哈希、归属人指纹、签名辅助、过期判断。"""

from __future__ import annotations

import base64

from ..primitives.group import deser_point, ser_point
from ..primitives.schnorr import SchnorrSig, verify as schnorr_verify
from .encoding import digest, encode
from .pke import canonical_json
from .schema import PHCv1, to_jsonld


class ProtocolError(PermissionError):
    """协议消息不成立：签名不对、绑定不一致、过期、身份对不上。"""


def hid_of(id_str: str) -> int:
    """H(ID)。ID 是身份证号这类低熵值 —— H(ID) 因而不是匿名标识，只能放在受控边界内。"""
    if not id_str:
        raise ProtocolError("PII 缺少 ID")
    return int.from_bytes(digest("HID", id_str), "big")


def owner_of(sign_pk) -> str:
    """槽位归属人：用户签名公钥的指纹。只有持有对应私钥的人能产生通过校验的请求。"""
    return "fpr:" + digest("owner", ser_point(sign_pk)).hex()[:40]


def pk_hex(pk) -> str:
    return ser_point(pk).hex()


def pk_from_hex(h: str):
    return deser_point(bytes.fromhex(h))


def sign(hsm, tag: str, *fields) -> str:
    return hsm.sign(encode(tag, *fields)).to_bytes().hex()


def check_sig(pk, sig_hex: str, tag: str, *fields, what: str) -> None:
    try:
        ok = schnorr_verify(pk, encode(tag, *fields), SchnorrSig.from_bytes(bytes.fromhex(sig_hex)))
    except (ValueError, TypeError):
        ok = False
    if not ok:
        raise ProtocolError(f"{what} 签名无效")


def json_digest(obj) -> str:
    return digest("json", canonical_json(obj)).hex()


def phc_digest(phc: PHCv1) -> str:
    return json_digest(to_jsonld(phc))


def not_expired(expires: str, now: str, what: str) -> None:
    """时间统一用 ISO-8601（YYYY-MM-DDTHH:MM:SS），同格式下字符串序即时间序。"""
    if not expires or expires <= now:
        raise ProtocolError(f"{what} 已过期或缺少有效期（expires={expires!r}, now={now!r}）")


def b64u(obj) -> str:
    return base64.urlsafe_b64encode(canonical_json(obj)).decode().rstrip("=")


def unb64u(s: str):
    import json
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad))


__all__ = ["ProtocolError", "hid_of", "owner_of", "pk_hex", "pk_from_hex", "sign",
           "check_sig", "json_digest", "phc_digest", "not_expired", "b64u", "unb64u"]
