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
    """测试用固定时钟：让"吊销时间"成为可断言的值，而不是一个范围。"""

    def __init__(self, at: str = "2026-01-01T00:00:00") -> None:
        self.at = at

    def now(self) -> str:
        return self.at

    def plus_hours(self, hours: int) -> str:
        from datetime import datetime, timedelta

        t = datetime.strptime(self.at, "%Y-%m-%dT%H:%M:%S") + timedelta(hours=hours)
        return t.strftime("%Y-%m-%dT%H:%M:%S")


__all__ = ["SystemClock", "FixedClock"]
