"""Schnorr 签名 / 验签（secp256k1）。

对应说明书参数表里的 Sig / Ver。

    签名： k ←$ Z_N ;  R = k·G ;  e = H(ser(R) ‖ ser(pk) ‖ m) ;  s = k + e·sk  (mod N)
    验签： s·G == R + e·pk

e 必须绑定 R 与 pk，否则会出现"一个签名适配多个公钥/消息"的可延展性问题。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from secrets import randbelow

from .group import G, N, Point, point_add, point_mul, ser_point


@dataclass(frozen=True)
class SchnorrSig:
    R: Point
    s: int

    def to_bytes(self) -> bytes:
        return ser_point(self.R) + self.s.to_bytes(32, "big")

    @staticmethod
    def from_bytes(b: bytes) -> "SchnorrSig":
        """从 65 字节还原：33 字节压缩点 + 32 字节 s。"""
        if len(b) != 65:
            raise ValueError(f"签名长度应为 65 字节，实际 {len(b)}")
        x = int.from_bytes(b[1:33], "big")
        y = _lift_x(x, b[0])
        return SchnorrSig(R=(x, y, 1), s=int.from_bytes(b[33:], "big"))


def _lift_x(x: int, prefix: int) -> int:
    """由压缩格式恢复 y（secp256k1 上 p ≡ 3 mod 4，可直接开方）。"""
    from .group import P

    alpha = (pow(x, 3, P) + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if (y & 1) != (prefix & 1):
        y = (-y) % P
    return y


def challenge(R: Point, pk: Point, msg: bytes) -> int:
    h = hashlib.sha256()
    h.update(ser_point(R))
    h.update(ser_point(pk))
    h.update(msg)
    return int.from_bytes(h.digest(), "big") % N or 1


def sign(sk: int, msg: bytes, k: int | None = None) -> SchnorrSig:
    if k is None:
        k = randbelow(N - 1) + 1
    R = point_mul(k)
    pk = point_mul(sk % N)
    e = challenge(R, pk, msg)
    return SchnorrSig(R=R, s=(k + e * (sk % N)) % N)


def verify(pk: Point, msg: bytes, sig: SchnorrSig) -> bool:
    if pk is None or sig.R is None:
        return False
    if not (1 <= sig.s < N):
        return False
    e = challenge(sig.R, pk, msg)
    lhs = point_mul(sig.s)
    rhs = point_add(sig.R, point_mul(e, pk))
    return lhs == rhs
