"""密钥派生 KDF —— 对应说明书"通过密钥派生函数（KDF）计算加密密钥"。

标准库没有 HKDF，这里用 HMAC-SHA256 的 extract-expand 结构实现（与 RFC 5869 同构）。
生产环境建议直接用 `cryptography.hazmat.primitives.kdf.hkdf.HKDF`。
"""

from __future__ import annotations

import hashlib
import hmac


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_key(*seed_parts: bytes | str | int, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """把若干种子材料派生成对称密钥。

    种子可以是 RF、身份哈希、初始密钥因子等 —— 任何一个单独都推不出结果。
    """
    ikm = b"".join(
        p if isinstance(p, bytes) else (str(p).encode() if isinstance(p, (str, int)) else bytes(p))
        for p in seed_parts
    )
    prk = _extract(salt, ikm)
    return _expand(prk, info, length)
