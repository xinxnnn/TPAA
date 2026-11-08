"""DID 注册表的落盘实现（TP 库）。

一服务一库（§6）：这个文件只有 did-service 会写。
别的 TP 服务想知道"谁的父亲是谁"，走 API 问它，不许直接开这个文件。

存的是 `DidRecord.to_json()` —— 注意那个方法**故意不含 cscid**。
要写盘就得另存一份全字段的，所以这里用 `_to_file()` 单独序列化：
对外响应与落盘内容分离，才不会出现"为了存起来而顺手把它发出去"。
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore, StoreError

from ..domain.entities import DidRecord


class DidRegistry:
    """注册表。读写都过 `JsonStore`，因此写盘是原子的。"""

    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path)
        self._lock = threading.RLock()

    # ---- 读写 ----

    def get(self, did: str) -> DidRecord | None:
        with self._lock:
            raw = self.store.load().get("records", {}).get(did)
            return DidRecord.from_json(raw) if raw else None

    def put(self, rec: DidRecord) -> None:
        with self._lock:
            def _fn(data: dict) -> dict:
                data.setdefault("records", {})[rec.did] = _to_file(rec)
                return data
            self.store.update(_fn)

    def all(self) -> dict[str, DidRecord]:
        with self._lock:
            recs = self.store.load().get("records", {})
            return {d: DidRecord.from_json(r) for d, r in recs.items()}

    def count(self) -> int:
        return len(self.all())

    # ---- 访问留痕（CSCID 揭示）----

    def log_access(self, *, did: str, case_ref: str, requested_by: str,
                   at: str) -> None:
        """记一条取用。★ 只追加，不提供删除 —— 取用记录能被删就失去意义。"""
        with self._lock:
            def _fn(data: dict) -> dict:
                data.setdefault("cscidAccess", []).append(
                    {"did": did, "caseRef": case_ref,
                     "requestedBy": requested_by, "at": at})
                return data
            self.store.update(_fn)

    def access_log(self) -> list[dict]:
        return list(self.store.load().get("cscidAccess", []))

    # ---- 自检 ----

    def self_check(self) -> None:
        """确认库可读、目录可写、且现存内容结构成立。"""
        try:
            data = self.store.load()
        except StoreError:
            raise
        except Exception as exc:                     # noqa: BLE001
            raise StoreError(f"DID 注册表不可读：{exc}") from exc
        recs = data.get("records", {})
        if not isinstance(recs, dict):
            raise StoreError("DID 注册表结构损坏：records 应为对象")
        # 探一次写：目录不可写要在启动时发现，而不是第一次登记时
        if not self.store.path.exists():
            self.store.save(data)


def _to_file(rec: DidRecord) -> dict:
    """落盘形态：比对外响应多一个 cscid（密文），其余一致。"""
    d = rec.to_json()
    d["cscid"] = rec.cscid
    return d


__all__ = ["DidRegistry"]
