"""coordination 的共享上下文与启动自检。

自检里有一条容易被人删掉的检查：**审计归档必须可用**。
一条没留痕的协查，事后无法证明"TP 到底问了什么" ——
而那正是取证包里最容易被对方质疑的一段。
所以宁可通道起不来，也不接受一个"能干活但不记账"的通道。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .rate_limit import Quota, RateLimiter


class ConfigError(RuntimeError):
    """启动自检未通过。"""


@dataclass
class CoordinationContext:
    tickets: object                 # TicketStore
    audit: object                   # AuditSink
    clock: object                   # Clock
    limiter: RateLimiter = field(default_factory=RateLimiter)
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []
        for name in ("tickets", "audit", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        if self.tickets is not None:
            try:
                self.tickets.self_check()
            except Exception as exc:                 # noqa: BLE001
                errors.append(f"工单库不可用：{exc}")

        if self.audit is None:
            errors.append("审计归档缺失：不留痕的协查事后无法举证")
        else:
            # ★ 真的探一次，而不是只看它是不是 None：
            #   一个接不上 audit-service 的 sink 同样"不是 None"，
            #   但它会在每次协查时静默丢记录。
            probe = getattr(self.audit, "probe", None)
            if callable(probe):
                try:
                    ok, why = probe()
                    if not ok:
                        errors.append(f"审计归档不可用：{why}")
                except Exception as exc:              # noqa: BLE001
                    errors.append(f"审计归档探测异常：{exc}")
        return errors

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError(
                "coordination 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["CoordinationContext", "ConfigError", "Quota", "RateLimiter"]
