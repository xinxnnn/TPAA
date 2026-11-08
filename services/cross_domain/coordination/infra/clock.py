"""时钟实现（跨域区各服务共用同一形态，便于测试时统一替换）。"""

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
        """推进时间 —— 限流的窗口判定需要它。"""
        self.at = at

    def plus_hours(self, hours: int) -> str:
        t = datetime.strptime(self.at, "%Y-%m-%dT%H:%M:%S") + timedelta(hours=hours)
        return t.strftime("%Y-%m-%dT%H:%M:%S")


__all__ = ["SystemClock", "FixedClock"]
