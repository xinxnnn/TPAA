"""tpaa_v1 规范化编码（errata K3）：所有签名消息、哈希输入都经这里。

proto0 的 `_h` 把字段直接拼接：("ab", "c") 与 ("a", "bc") 得到同一串字节，
不同的字段组合可以算出同一个哈希。这里改成：

    encode(tag, f1, f2, ...) =
        len(tag) ‖ "TPAA/v1/" + tag ‖ 字段个数 ‖ Σ ( 类型 ‖ len ‖ 值 )

    类型：i 非负整数（大端最短）  s UTF-8 字符串  b 字节串  n 空值

★ tag 做域分离：TPproof 的消息永远不可能与 CHproof 的消息相同，
  一个签名不能被挪到另一个用途上。
★ bool 被拒绝：True 会被当成整数 1，与真正的 1 编码相同。
"""

from __future__ import annotations

import hashlib

TAG_PREFIX = b"TPAA/v1/"


def _len(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _field(v) -> bytes:
    if v is None:
        return b"n" + _len(0)
    if isinstance(v, bool):
        raise TypeError("bool 不进规范化编码（与整数 0/1 不可区分）")
    if isinstance(v, int):
        if v < 0:
            raise ValueError("规范化编码只收非负整数")
        raw, kind = v.to_bytes((v.bit_length() + 7) // 8, "big"), b"i"
    elif isinstance(v, str):
        raw, kind = v.encode("utf-8"), b"s"
    elif isinstance(v, (bytes, bytearray)):
        raw, kind = bytes(v), b"b"
    else:
        raise TypeError(f"不支持的字段类型：{type(v).__name__}")
    return kind + _len(len(raw)) + raw


def encode(tag: str, *fields) -> bytes:
    t = TAG_PREFIX + tag.encode("utf-8")
    return _len(len(t)) + t + _len(len(fields)) + b"".join(_field(f) for f in fields)


def digest(tag: str, *fields) -> bytes:
    return hashlib.sha256(encode(tag, *fields)).digest()


def h_int(tag: str, *fields, mod: int) -> int:
    """哈希到 [1, mod)。"""
    return int.from_bytes(digest(tag, *fields), "big") % mod or 1


__all__ = ["encode", "digest", "h_int", "TAG_PREFIX"]
