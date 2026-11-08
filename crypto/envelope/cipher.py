"""对称加密（encrypt-then-MAC）。

零依赖实现：哈希 CTR 流加密 + HMAC-SHA256 认证标签。

⚠ 生产替换点：正式部署请改用 `cryptography` 的 AEAD
（如 ChaCha20-Poly1305 或 AES-GCM），不要在核心里自研。
此实现满足"加密 + 完整性"且结构简单可审计，仅用于验证协议流程。
"""

from __future__ import annotations

import hashlib
import hmac
from secrets import token_bytes

_BLOCK = 32


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return out[:length]


def encrypt(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """返回 (nonce, ciphertext, tag)。"""
    if len(key) < 16:
        raise ValueError("密钥太短")
    nonce = nonce or token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(key, nonce, len(plaintext))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce, ct, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
    """校验失败返回 None（不抛异常，由调用方决定如何处理）。"""
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        return None
    ks = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))
