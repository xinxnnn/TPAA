"""案件库（TP 库）。

一句话原则：**案件库可以被备份，但不能被浏览。**
    所以这里没有 `list_all()` 之外的批量查询能力，也没有"按举报人搜"这类接口 ——
    能按人搜的库，早晚会被用来按人查。
    （`all()` 仍然保留：立案页需要一个总览，而总览里不出现 H(ID)。）
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore, StoreError

from ..domain.entities import Case


class CaseStore:
    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path)
        self._lock = threading.RLock()

    def get(self, case_id: str) -> Case | None:
        with self._lock:
            raw = self.store.load().get("cases", {}).get(case_id)
            return Case.from_json(raw) if raw else None

    def put(self, case: Case) -> None:
        with self._lock:
            def _fn(data: dict) -> dict:
                data.setdefault("cases", {})[case.case_id] = case.to_json()
                return data
            self.store.update(_fn)

    def all(self) -> dict[str, Case]:
        with self._lock:
            return {k: Case.from_json(v)
                    for k, v in self.store.load().get("cases", {}).items()}

    def self_check(self) -> None:
        data = self.store.load()
        if not isinstance(data.get("cases", {}), dict):
            raise StoreError("案件库结构损坏：cases 应为对象")
        if not self.store.path.exists():
            self.store.save(data)


__all__ = ["CaseStore"]
