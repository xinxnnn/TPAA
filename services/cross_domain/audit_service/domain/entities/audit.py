"""审计条目与哈希链。

链的形态刻意选得最朴素：

    hash_i = H( hash_{i-1} ‖ 规范化载荷_i )

因为它要能被任意第三方独立复算 —— 不需要我们的代码、不需要我们的密钥，
只要有一份记录列表和标准库的 sha256。用签名反而更差：
签名只能证明"是我们写的"，证明不了"第 7 条发布之后没被改过"。

★ 环检测与逐层比对都走 `crypto.sdk`（红线 2）。
  这不是为了好看：审计链是全系统唯一"必须自己证明自己没被动过"的结构，
  它的哈希实现不该有第二份，否则两份实现之间的一点差异就足以让整个举证失效。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

import crypto.sdk


def canonical(payload: dict) -> str:
    """规范化：键排序、无空格、UTF-8。同一份内容必须得到同一个字符串。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    entry_id: str
    at: str
    kind: str
    subject: str
    payload: dict = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def to_json(self) -> dict:
        return {
            "seq": self.seq, "entryId": self.entry_id, "at": self.at,
            "kind": self.kind, "subject": self.subject,
            "payload": self.payload, "prevHash": self.prev_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_json(cls, d: dict) -> "AuditEntry":
        return cls(
            seq=int(d.get("seq", 0)), entry_id=d.get("entryId", ""),
            at=d.get("at", ""), kind=d.get("kind", ""),
            subject=d.get("subject", ""), payload=d.get("payload", {}) or {},
            prev_hash=d.get("prevHash", ""), hash=d.get("hash", ""),
        )

    def expected_hash(self) -> str:
        """本条目**应有**的哈希。用它和存下来的 hash 比，就知道有没有被改。"""
        return entry_hash(prev_hash=self.prev_hash, at=self.at, kind=self.kind,
                          subject=self.subject, payload=self.payload,
                          entry_id=self.entry_id, seq=self.seq)


def entry_hash(*, prev_hash: str, at: str, kind: str, subject: str,
               payload: dict, entry_id: str, seq: int) -> str:
    """计算一条审计记录的哈希。

    ★ 参与计算的字段包含 seq 与 entry_id —— 否则"插入一条"这种攻击查不出来：
      只在中间插一条，前后指针都接得上，哈希也各自自洽。
      把序号与编号也混进去之后，插入必然导致后续所有条目的 prev_hash 对不上。
    """
    parts = [
        prev_hash,
        str(seq),
        entry_id,
        at,
        kind,
        subject,
        canonical(payload),
    ]
    return crypto.sdk.hash_chain(parts).hex()


@dataclass(frozen=True)
class ChainVerdict:
    """整链核验结论。"""

    ok: bool
    length: int
    broken_at: int = -1              # 第一个出问题的 seq；-1 表示没问题
    reason: str = ""

    def to_json(self) -> dict:
        return {"ok": self.ok, "length": self.length,
                "brokenAt": self.broken_at, "reason": self.reason}


def verify_entries(entries: list[AuditEntry]) -> ChainVerdict:
    """从头复算一遍整条链。

    检查两件事，缺一不可：
        1  每条自己的哈希是否等于按内容复算的哈希（内容被改）
        2  每条指向的上一条哈希是否等于上一条的哈希（被插、被删、被调序）
    """
    prev = ""
    for i, e in enumerate(entries):
        if e.expected_hash() != e.hash:
            return ChainVerdict(ok=False, length=len(entries), broken_at=e.seq,
                                reason=f"第 {e.seq} 条内容与其哈希不符（内容被改）")
        if e.prev_hash != prev:
            return ChainVerdict(ok=False, length=len(entries), broken_at=e.seq,
                                reason=(f"第 {e.seq} 条指向的上一条哈希不匹配"
                                        "（曾被插入、删除或调序）"))
        prev = e.hash
    return ChainVerdict(ok=True, length=len(entries))


def digest_of(obj: dict | str) -> str:
    """任意对象的摘要 —— 用于"存证"：只留指纹、留原文由调用方决定。"""
    s = obj if isinstance(obj, str) else canonical(obj)
    return hashlib.sha256(s.encode()).hexdigest()


__all__ = [
    "AuditEntry", "ChainVerdict", "canonical", "entry_hash",
    "verify_entries", "digest_of",
]
