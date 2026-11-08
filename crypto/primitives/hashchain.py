"""哈希链 HCGen —— 智能体代码的技术溯源。

    h_i = H( h_{i-1} ‖ item_i )      最终 h_n 即配置承诺 CMI

保留逐层中间值是刻意的：更新与找回时可以做增量比对，
而不必每次都从头重算整个链。
"""

from __future__ import annotations

import hashlib
from typing import Sequence

GENESIS = b"\x00" * 32


def _to_bytes(x: bytes | str) -> bytes:
    return x if isinstance(x, bytes) else x.encode("utf-8")


def hash_chain(items: Sequence[bytes | str]) -> bytes:
    acc = GENESIS
    for it in items:
        acc = hashlib.sha256(acc + _to_bytes(it)).digest()
    return acc


def hash_chain_layers(items: Sequence[bytes | str]) -> list[bytes]:
    acc = GENESIS
    out: list[bytes] = []
    for it in items:
        acc = hashlib.sha256(acc + _to_bytes(it)).digest()
        out.append(acc)
    return out


def verify_chain(items: Sequence[bytes | str], expected: bytes) -> bool:
    return hash_chain(items) == expected


def first_divergence(a: Sequence[bytes], b: Sequence[bytes]) -> int | None:
    """两组逐层值的第一个分歧位置；None 表示完全一致。"""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return None
