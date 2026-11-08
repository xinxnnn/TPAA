"""audit-service 的共享上下文与启动自检。

自检分两档，刻意分开：

    preflight()   **阻断项**：缺了就不许启动。审计链断了、账本不可写、没有时钟。
    warnings()    **降级项**：能跑，但某项能力缺失，要在 /healthz 上一直看得见。

为什么"没配存证去处"只算降级而不阻断：
    一个只做记录、暂时不存 PHC 原文的审计服务，仍然比一个起不来的审计服务有用 ——
    至少协查的往返记录还在。但这件事必须一直挂在 /healthz 上，
    否则三个月后没人记得"我们的子体 PHC 其实没存证"。

★ 启动时就把整条链核验一遍：
    链断了要第一时间知道。等到取证那天才发现"第 41 条对不上"，
    排查范围会扩散到过去几个月的所有操作；启动时发现，范围就缩到"上次重启之后"。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """启动自检未通过。"""


@dataclass
class AuditContext:
    ledger: object                  # LedgerPort
    attest: object                  # AttestSink | None
    clock: object                   # Clock
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []

        # 1) 链路完整性 —— 唯一会让人停下来的一项
        if self.ledger is not None:
            try:
                self.ledger.self_check()
            except Exception as exc:              # noqa: BLE001
                errors.append(f"审计账本不可用：{exc}")

        # 2) 时钟
        if self.clock is None:
            errors.append("缺少端口：clock")

        return errors

    def warnings(self) -> list[str]:
        out: list[str] = []

        if self.attest is None:
            out.append("未配置子体 PHC 存证去处：存证调用会失败（attest 端口为空）")

        # 非阻断的链核验：账本可读但链断了 —— 允许起来看图，但不许追加
        if self.ledger is not None:
            from ..entities import verify_entries

            try:
                verdict = verify_entries(self.ledger.all())
            except Exception as exc:              # noqa: BLE001
                out.append(f"审计链无法解析：{exc}")
            else:
                if not verdict.ok:
                    out.append(
                        f"审计链已断于第 {verdict.broken_at} 条：{verdict.reason}")

        return out

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError(
                "audit-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["AuditContext", "ConfigError"]
