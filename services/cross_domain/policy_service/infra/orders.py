"""吊销令库（跨域区）。

吊销令是**最不应该被编辑的一类记录**：它决定了谁的智能体被关掉。
所以这里同样只有 put/get/all，没有 delete。
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore, StoreError

from ..domain.entities import RevocationOrder


class OrderStore:
    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path)
        self._lock = threading.RLock()

    def put(self, order: RevocationOrder) -> None:
        with self._lock:
            def _fn(data: dict) -> dict:
                data.setdefault("orders", {})[order.order_id] = order.to_json()
                return data
            self.store.update(_fn)

    def get(self, order_id: str) -> RevocationOrder | None:
        with self._lock:
            raw = self.store.load().get("orders", {}).get(order_id)
            return RevocationOrder.from_json(raw) if raw else None

    def all(self) -> dict[str, RevocationOrder]:
        with self._lock:
            return {k: RevocationOrder.from_json(v)
                    for k, v in self.store.load().get("orders", {}).items()}

    def self_check(self) -> None:
        data = self.store.load()
        if not isinstance(data.get("orders", {}), dict):
            raise StoreError("吊销令库结构损坏：orders 应为对象")
        if not self.store.path.exists():
            self.store.save(data)


__all__ = ["OrderStore"]
