"""审计账本：只追加、不修改、不删除。

★ 这个类**刻意没有** update / delete 方法。
  不是忘了 —— 一个"能改的审计表"在法庭上没有证明力，
  而且只要方法存在，早晚会有人在某个"修数据"的脚本里用它。

★ seq 与 prev_hash 在这里生成，不接受调用方传值（理由见 record.py）。
  写入过程整体加锁：两条并发追加如果同时读到同一个 tail，
  就会得到两个 seq 相同、prev_hash 相同的条目 —— 链当场分叉。
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore, StoreError

from ..domain.entities import AuditEntry, entry_hash


class AuditLedger:
    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path, default={"entries": []})
        self._lock = threading.RLock()

    # ---- 追加 ----

    def append(self, *, at: str, kind: str, subject: str,
               payload: dict) -> AuditEntry:
        with self._lock:
            data = self.store.load()
            entries = list(data.get("entries", []))

            seq = len(entries) + 1
            prev_hash = entries[-1]["hash"] if entries else ""
            entry_id = f"ae-{seq:06d}"

            h = entry_hash(prev_hash=prev_hash, at=at, kind=kind,
                           subject=subject, payload=payload,
                           entry_id=entry_id, seq=seq)
            entry = AuditEntry(seq=seq, entry_id=entry_id, at=at, kind=kind,
                               subject=subject, payload=dict(payload),
                               prev_hash=prev_hash, hash=h)
            entries.append(entry.to_json())
            self.store.save({**data, "entries": entries})
            return entry

    # ---- 读 ----

    def all(self) -> list[AuditEntry]:
        with self._lock:
            return [AuditEntry.from_json(d) for d in self.store.load().get("entries", [])]

    def get(self, entry_id: str) -> AuditEntry | None:
        for e in self.all():
            if e.entry_id == entry_id:
                return e
        return None

    def tail(self) -> AuditEntry | None:
        items = self.all()
        return items[-1] if items else None

    def self_check(self) -> None:
        data = self.store.load()
        if not isinstance(data.get("entries", []), list):
            raise StoreError("审计账本结构损坏：entries 应为数组")
        if not self.store.path.exists():
            self.store.save(data)


__all__ = ["AuditLedger"]
