"""did-service 的共享上下文与启动自检。

★ 这里持有的是**监管公钥形态**，不是密钥。
    封存（seal）人人可做，还原（open）只有监管域能做 —— 分界就在这个类型上。
    如果哪天这里出现 `SupervisionKey`，说明有人把解密权塞进了号码簿，
    而号码簿是被追溯链高频读取的地方，那等于把钥匙挂在门上。

自检检查的都是"错了一时半会儿看不出来"的东西：
    监管公钥是 0 或 1 位数的假货、库目录不可写、库已损坏。
    这些都不会在第一次请求时报错，只会在某次追溯取不出身份时才发现。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ports import Clock


class ConfigError(RuntimeError):
    """启动自检未通过。宁可起不来，也不带病启动。"""


@dataclass
class DidContext:
    registry: object            # DidRegistry
    supervision_pub: object     # crypto.sdk.SupervisionPublic（只可封存）
    clock: Clock
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []

        # 1) 必须拿到**公钥形态**：完整密钥形态出现在这里即为装配错误
        cls = type(self.supervision_pub).__name__
        if cls != "SupervisionPublic":
            errors.append(
                f"监管密钥必须是公钥形态 SupervisionPublic，实际 {cls} —— "
                "did-service 只负责封存，无权还原身份")

        n = getattr(self.supervision_pub, "n", 0)
        if not isinstance(n, int) or n < 2 ** 512:
            errors.append(f"监管公钥异常（n 的位数不足）：这把钥匙解不开任何东西")

        # 2) 库可写
        try:
            self.registry.self_check()
        except Exception as exc:                    # noqa: BLE001 - 落盘层各类故障
            errors.append(f"DID 注册表不可用：{exc}")

        # 3) 时钟齐备
        if self.clock is None:
            errors.append("缺少端口：clock")

        return errors

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError("did-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["DidContext", "ConfigError"]
