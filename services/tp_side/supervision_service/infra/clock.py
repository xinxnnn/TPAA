"""时钟实现。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class SystemClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    def plus_hours(self, hours: int) -> str:
        t = datetime.now(timezone.utc) + timedelta(hours=hours)
        return t.strftime("%Y-%m-%dT%H:%M:%S")


class FixedClock:
    def __init__(self, at: str = "2026-01-01T00:00:00") -> None:
        self.at = at

    def now(self) -> str:
        return self.at

    def set(self, at: str) -> None:
        self.at = at


__all__ = ["SystemClock", "FixedClock"]
