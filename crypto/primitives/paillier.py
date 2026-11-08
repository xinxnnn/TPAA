"""Paillier 加法同态加密 —— TP 用它把身份哈希封进监管因子 RF。

    Enc(a) · Enc(b) = Enc(a + b)   (mod n²)

生产要求：
    - n ≥ 3072 bit（演示时可降到 2048 提速）
    - 随机因子 r ∈ Z*_n，每次加密独立取样
    - 明文 m 必须 < n（H(ID) 为 256 bit，安全）

⚠ 已知坑（本项目踩过）：
    求 μ 需要模逆，而模数 n 是**合数**，绝不能用费马小定理
    pow(a, n-2, n)，必须走拓展欧几里得 pow(a, -1, n)。
"""

from __future__ import annotations

import hashlib
import hmac
from secrets import randbelow
from typing import Callable


# ---------------------------------------------------------------------------
# 数论工具
# ---------------------------------------------------------------------------


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    return a // gcd(a, b) * b


def inverse_mod(a: int, m: int) -> int:
    """模逆。m 不要求是素数，故不能用费马小定理。"""
    return pow(a % m, -1, m)


def is_probable_prime(
    n: int, rounds: int = 24, *, randbelow_fn: Callable[[int], int] = randbelow,
) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = randbelow_fn(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, *, randbelow_fn: Callable[[int], int] = randbelow) -> int:
    while True:
        cand = randbelow_fn(1 << bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(cand, randbelow_fn=randbelow_fn):
            return cand


class _SeededKeyRandom:
    """Deterministic HMAC-SHA256 stream used only to reproduce local test keys."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) < 32:
            raise ValueError("deterministic Paillier key seed must contain at least 32 bytes")
        self.seed = seed
        self.counter = 0

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper bound must be positive")
        width = (upper.bit_length() + 7) // 8
        mask = (1 << upper.bit_length()) - 1
        while True:
            output = bytearray()
            while len(output) < width:
                block = hmac.new(
                    self.seed, self.counter.to_bytes(16, "big"), hashlib.sha256).digest()
                self.counter += 1
                output.extend(block)
            candidate = int.from_bytes(output[:width], "big") & mask
            if candidate < upper:
                return candidate


def _l_func(x: int, n: int) -> int:
    """Paillier 的 L 函数：L(x) = (x − 1) / n。"""
    return (x - 1) // n


# ---------------------------------------------------------------------------
# Paillier
# ---------------------------------------------------------------------------


class Paillier:
    """标准 Paillier 方案，取 g = n + 1（此时 L(g^λ mod n²) = λ）。"""

    def __init__(self, bits: int = 3072, *, seed: bytes | None = None) -> None:
        if bits < 2048:
            raise ValueError("Paillier n 至少 2048 bit；生产建议 ≥3072")
        random_source = _SeededKeyRandom(seed) if seed is not None else None
        key_randbelow = random_source.randbelow if random_source else randbelow
        half = bits // 2
        p = gen_prime(half, randbelow_fn=key_randbelow)
        q = gen_prime(half, randbelow_fn=key_randbelow)
        while q == p:
            q = gen_prime(half, randbelow_fn=key_randbelow)
        self.p = p
        self.q = q
        self.n = p * q
        self.nsq = self.n * self.n
        self.g = self.n + 1
        self.lam = lcm(p - 1, q - 1)
        u = pow(self.g, self.lam, self.nsq)
        self.mu = inverse_mod(_l_func(u, self.n), self.n)

    def encrypt(self, m: int, r: int | None = None) -> int:
        if not 0 <= m < self.n:
            raise ValueError("明文必须小于 n")
        if r is None:
            r = randbelow(self.n - 1) + 1
        g_m = pow(self.g, m, self.nsq)
        r_n = pow(r, self.n, self.nsq)
        return g_m * r_n % self.nsq

    def decrypt(self, c: int) -> int:
        inner = pow(c, self.lam, self.nsq)
        return _l_func(inner, self.n) * self.mu % self.n

    def add(self, c1: int, c2: int) -> int:
        """Enc(a) · Enc(b) = Enc(a + b)。"""
        return c1 * c2 % self.nsq

    def mul_const(self, c: int, k: int) -> int:
        """密文乘常数：Enc(m)^k = Enc(k·m)。"""
        return pow(c, k, self.nsq)
