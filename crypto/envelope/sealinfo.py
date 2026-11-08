"""SecInfo 加密信封 —— G2 打包、R2 拆封，以及 CID 的保护。

这是 **找回（T1）与追溯（R2）的公共内核**，只允许有这一份实现。

    G2：seal_secinfo()  → 密文信封 → 上传 IPFS → CID → protect_cid() → ECID
    R2：recover_cid()   → CID → 从 IPFS 取回 → unseal_secinfo() → BI / PII
"""

from __future__ import annotations

import json

from .cipher import decrypt, encrypt
from .kdf import derive_key


# ---------------------------------------------------------------------------
# SecInfo 信封
# ---------------------------------------------------------------------------


def seal_secinfo(
    *,
    bi: bytes,
    pii: bytes,
    seed_parts: tuple | list,
) -> tuple[bytes, bytes, bytes, bytes]:
    """把生物特征与身份信息封进信封。返回 (key, nonce, ciphertext, tag)。

    seed_parts 是派生密钥的种子材料（RF / 初始密钥因子等）——
    它们**不出现在返回值里**，由 TP 单独保管。
    """
    key = derive_key(*seed_parts, info=b"tpaa/secinfo/v1")
    payload = json.dumps({"bi": bi.hex(), "pii": pii.hex()}).encode()
    nonce, ct, tag = encrypt(key, payload)
    return key, nonce, ct, tag


def unseal_secinfo(
    *,
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> tuple[bytes, bytes] | None:
    """拆封。校验失败返回 None。"""
    payload = decrypt(key, nonce, ciphertext, tag)
    if payload is None:
        return None
    obj = json.loads(payload)
    return bytes.fromhex(obj["bi"]), bytes.fromhex(obj["pii"])


# ---------------------------------------------------------------------------
# CID 的保护（红线 17：CID 不得明文落盘）
# ---------------------------------------------------------------------------


def _cid_key(key: bytes) -> bytes:
    return derive_key(key, info=b"tpaa/cid/v1")


def protect_cid(cid: str, key: bytes) -> str:
    """CID → ECID。任何拿到 ECID 的人都无法去 IPFS 取件。"""
    nonce, ct, tag = encrypt(_cid_key(key), cid.encode())
    return json.dumps([nonce.hex(), ct.hex(), tag.hex()])


def recover_cid(ecid: str, key: bytes) -> str | None:
    """ECID → CID。只有持有密钥的 TP 能解。"""
    nonce_hex, ct_hex, tag_hex = json.loads(ecid)
    result = decrypt(
        _cid_key(key),
        bytes.fromhex(nonce_hex),
        bytes.fromhex(ct_hex),
        bytes.fromhex(tag_hex),
    )
    return result.decode() if result is not None else None
