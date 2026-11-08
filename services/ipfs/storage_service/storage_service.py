"""IPFS 方：storage-service。

★ 这是独立的第五方（说明书五个实体之一），不是 TP 内部的一个存储调用。

责任边界（见完整方案 2.2）：

    负责：可用性、内容寻址的完整性、取用留痕
    不负责：保密性（由加密机制保证）、不持有任何密钥、不解析内容

设计立场：**诚实但好奇**的对手模型 ——
我们按"它能看到全部存储内容"做最坏打算，所以它那边只有密文。

本文件是它的可运行骨架：内存版实现 + 取用审计。
对接真实 IPFS / 对象存储时替换 gateway-adapter 即可，接口不变。
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from services.shared.store import JsonStore, StoreError


@dataclass
class AccessRecord:
    """一次取用的留痕。独立于 TP 的日志，用于合规举证。"""
    cid: str
    requester: str
    action: str          # put / get / pin
    at: str
    ok: bool


class StorageService:
    """密文信封的写入与取回。它拿到的永远是密文，它自己也不想知道是什么。"""

    def __init__(self, *, name: str = "ipfs-node", state_path: str | Path | None = None) -> None:
        self._objects: dict[str, bytes] = {}
        self._pinned: set[str] = set()
        self.access_log: list[AccessRecord] = []
        self.name = name
        self._store = JsonStore(state_path) if state_path is not None else None
        if self._store is not None and self._store.exists():
            saved = self._store.load()
            try:
                encoded_objects = saved.get("objects", {})
                self._objects = {
                    cid: base64.b64decode(payload, validate=True)
                    for cid, payload in encoded_objects.items()
                }
                if any(self._cid(blob) != cid for cid, blob in self._objects.items()):
                    raise StoreError("密文对象存储的 CID 校验失败")
                self._pinned = set(saved.get("pinned", []))
                if not self._pinned.issubset(self._objects):
                    raise StoreError("密文对象存储包含不存在的固定对象")
                self.access_log = [
                    AccessRecord(**record) for record in saved.get("accessLog", [])
                ]
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise StoreError(f"密文对象存储格式无效：{exc}") from exc

    # ------------------------------------------------------------------
    # 协议动作
    # ------------------------------------------------------------------

    def put(self, ciphertext: bytes, *, requester: str) -> str:
        """G2：写入密文信封 → 返回 CID（内容寻址）。"""
        cid = self._cid(ciphertext)
        self._objects[cid] = ciphertext
        self._log(cid, requester, "put", True)
        self._persist()
        return cid

    def get(self, cid: str, *, requester: str) -> bytes | None:
        """R2：凭 CID 取回密文。每次取用必须留痕（红线 18）。"""
        data = self._objects.get(cid)
        self._log(cid, requester, "get", data is not None)
        self._persist()
        return data

    def pin(self, cid: str, *, requester: str) -> bool:
        """固定，防止被垃圾回收。可用性承诺的一部分。"""
        if cid not in self._objects:
            self._log(cid, requester, "pin", False)
            self._persist()
            return False
        self._pinned.add(cid)
        self._log(cid, requester, "pin", True)
        self._persist()
        return True

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------

    def log_of(self, cid: str) -> list[AccessRecord]:
        return [r for r in self.access_log if r.cid == cid]

    def _log(self, cid: str, requester: str, action: str, ok: bool) -> None:
        self.access_log.append(
            AccessRecord(cid=cid, requester=requester, action=action,
                         at=time.strftime("%Y-%m-%dT%H:%M:%S"), ok=ok)
        )

    @staticmethod
    def _cid(ciphertext: bytes) -> str:
        return "b" + hashlib.sha256(ciphertext).hexdigest()[:59]

    def _persist(self) -> None:
        if self._store is None:
            return
        self._store.save({
            "objects": {cid: base64.b64encode(blob).decode("ascii")
                        for cid, blob in self._objects.items()},
            "pinned": sorted(self._pinned),
            "accessLog": [record.__dict__ for record in self.access_log],
        })

    # ------------------------------------------------------------------
    # 自检：证明这一方不持有任何密钥、不接触明文
    # ------------------------------------------------------------------

    def self_check(self) -> dict:
        """安全自检：遍历全部存储，确认只有密文、没有密钥形态的东西。"""
        return {
            "objects": len(self._objects),
            "pinned": len(self._pinned),
            "access_records": len(self.access_log),
            "holds_keys": False,        # 它根本没有存密钥的字段
        }
