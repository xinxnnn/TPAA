"""gateway 的共享上下文与启动自检。

★ `allowed_kinds` 是**配置**，不是常量。

    它不是"技术上能不能答"，而是"本节点答应答哪几种"。
    一个只持有主凭证的 AP 节点，没有理由应答子体归属证明 ——
    让它继续答，就只能给出一份它其实不知道的答案。

★ 自检里有一条"通道必须可用"：
    一个收不到件的 gateway 是最危险的形态 ——
    它看起来在正常运行，健康检查也过（本机端口都在），
    但对岸开的每一张单子都在安静地过期。
    所以宁可起不来，也不要一个"活着但聋了"的边界。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """启动自检未通过。"""


_PARTIES = {"TP", "AP"}


@dataclass
class GatewayContext:
    channel: object                 # ChannelPort
    assist: object                  # AssistPort
    audit: object                   # AuditSink
    clock: object                   # Clock
    stop: object = None             # StopPort（承接吊销用；纯协查节点可为 None）
    self_id: str = "AP"             # 本方在通道里的名字
    allowed_kinds: tuple = ("lineage_proof",)
    batch_limit: int = 50           # 一次最多处理多少张 —— 背压
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []
        for name in ("channel", "assist", "audit", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        who = (self.self_id or "").strip().upper()
        if who not in _PARTIES:
            errors.append(f"self_id 必须是 TP 或 AP，当前是 {self.self_id!r}")

        if not tuple(self.allowed_kinds or ()):
            errors.append(
                "allowed_kinds 为空 —— 一个什么都不答的 gateway 没有存在意义；"
                "若确为有意，请显式确认而不是留空")

        if self.batch_limit <= 0:
            errors.append(f"batch_limit 必须为正，当前 {self.batch_limit}")

        # 真探一次通道：只看它是不是 None 不够，
        # 一个连不上 coordination 的适配器同样"不是 None"。
        if self.channel is not None:
            probe = getattr(self.channel, "probe", None)
            if callable(probe):
                try:
                    ok, why = probe()
                    if not ok:
                        errors.append(f"跨域通道不可用：{why}")
                except Exception as exc:              # noqa: BLE001
                    errors.append(f"跨域通道探测异常：{exc}")

        if self.audit is not None:
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
                "gateway 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["GatewayContext", "ConfigError"]
