"""工单库（跨域区自己的库）。

与 did-service 的注册表同一套路：一服务一库、原子写、坏文件不静默重置。
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore, StoreError

from ..domain.entities import Ticket


class TicketStore:
    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path)
        self._lock = threading.RLock()

    def get(self, ticket_id: str) -> Ticket | None:
        with self._lock:
            raw = self.store.load().get("tickets", {}).get(ticket_id)
            return Ticket.from_json(raw) if raw else None

    def put(self, ticket: Ticket) -> None:
        with self._lock:
            def _fn(data: dict) -> dict:
                data.setdefault("tickets", {})[ticket.ticket_id] = {
                    **ticket.to_json(), "answer": ticket.answer}
                return data
            self.store.update(_fn)

    def all(self) -> dict[str, Ticket]:
        with self._lock:
            return {k: Ticket.from_json(v)
                    for k, v in self.store.load().get("tickets", {}).items()}

    def self_check(self) -> None:
        data = self.store.load()
        if not isinstance(data.get("tickets", {}), dict):
            raise StoreError("工单库结构损坏：tickets 应为对象")
        if not self.store.path.exists():
            self.store.save(data)


__all__ = ["TicketStore"]
