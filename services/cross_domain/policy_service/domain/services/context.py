"""policy-service 的共享上下文与启动自检。

自检里有一条特别值得留着：**通知端口必须存在**。
    一个能把凭证吊销、但停不掉实例的 policy-service，
    在面板上看起来"吊销成功"，实际上那个智能体还在跑。
    这种半成功比彻底失败危险得多 —— 所以缺通知端口就不许启动。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """启动自检未通过。"""


@dataclass
class PolicyContext:
    orders: object                  # OrderStore
    directory: object               # DirectoryPort
    notify: object                  # NotifyPort
    audit: object                   # AuditSink
    clock: object                   # Clock
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []
        for name in ("orders", "directory", "notify", "audit", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        if self.orders is not None:
            try:
                self.orders.self_check()
            except Exception as exc:                 # noqa: BLE001
                errors.append(f"吊销令库不可用：{exc}")

        if self.audit is not None:
            probe = getattr(self.audit, "probe", None)
            if callable(probe):
                ok, why = probe()
                if not ok:
                    errors.append(f"审计归档不可用：{why}")

        return errors

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError(
                "policy-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["PolicyContext", "ConfigError"]
