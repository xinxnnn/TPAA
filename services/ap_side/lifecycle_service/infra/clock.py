"""系统时钟。抽出端口是为了让 TTL / 冻结时间在测试里可控。

一个刻意的细节：时间戳统一用 **UTC**，不用本地时间。
TTL 判定、冻结时间、审计留痕都要跨机器比对；一旦掺进时区，
两台机器上的"同一时刻"就会相差几个小时，而过期判定恰好是那种
"差几个小时也照样跑、只是结论错了"的错误。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_FMT = "%Y-%m-%dT%H:%M:%SZ"


class SystemClock:
    """真实时间。ISO 8601、秒级、UTC、带 Z 后缀。"""

    def now(self) -> str:
        return datetime.now(timezone.utc).strftime(_FMT)

    def plus_hours(self, hours: int) -> str:
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(_FMT)


class FixedClock:
    """测试与演练用：可以任意拨动，但拨动本身要留痕（advance 只进不退）。"""

    def __init__(self, start: str = "2026-01-01T00:00:00Z") -> None:
        self._t = datetime.strptime(start, _FMT).replace(tzinfo=timezone.utc)

    def now(self) -> str:
        return self._t.strftime(_FMT)

    def plus_hours(self, hours: int) -> str:
        return (self._t + timedelta(hours=hours)).strftime(_FMT)

    def advance(self, *, hours: int = 0, minutes: int = 0) -> None:
        self._t += timedelta(hours=hours, minutes=minutes)


__all__ = ["SystemClock", "FixedClock"]
