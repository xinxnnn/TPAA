"""限流：协查通道的配额。

为什么要限流：
    这条通道的另一端是**另一个责任方**。TP 可以在立案后合法地向 AP 索取随机因子，
    但"合法"不等于"无限" ——  unlimited 的索取接口在实践中会被当成探测工具：
    批量问"这个 DID 的随机因子是多少"，就能在没立案的情况下把归属关系摸出来。

所以限制的是**两件事**，缺一不可：

    max_open       同一时刻最多几张未决工单（防并发刷）
    max_per_hour   一小时内最多发起几张（防慢速扫）

另外一条更重要的规则：**没有案由（case_ref 为空）的协查，配额只有十分之一。**
    追溯是例外手段，不是常规查询。想常规查询，就该走别的接口。
    把它做成配额差异，是为了让"随手查一下"在体感上就不划算。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import RateLimited


@dataclass(frozen=True)
class Quota:
    max_open: int = 20
    max_per_hour: int = 60


class RateLimiter:
    def __init__(self, *, quota: Quota | None = None) -> None:
        self.quota = quota or Quota()

    def check(self, *, requester: str, tickets: dict, case_ref: str,
              now: str) -> None:
        """tickets: {ticket_id: Ticket}。不合规就抛 RateLimited。"""
        scale = 1 if case_ref else 10          # 无案由 → 配额收紧到 1/10
        max_open = max(self.quota.max_open // scale, 1)
        max_hour = max(self.quota.max_per_hour // scale, 1)

        mine = [t for t in tickets.values() if t.requester == requester]
        open_cnt = sum(1 for t in mine if t.state.value == "pending")
        if open_cnt >= max_open:
            raise RateLimited(
                f"{requester} 有 {open_cnt} 张未决工单，已达上限 {max_open}"
                + ("" if case_ref else "（无案由协查配额收紧为十分之一）"))

        # 一小时窗口按字符串前缀比：时间戳是 %Y-%m-%dT%H:%M:%S，取前 13 位即小时
        hour = now[:13]
        in_hour = sum(1 for t in mine if t.created_at[:13] == hour)
        if in_hour >= max_hour:
            raise RateLimited(
                f"{requester} 在 {hour} 时内已发起 {in_hour} 张工单，"
                f"已达上限 {max_hour}")


__all__ = ["Quota", "RateLimiter"]
