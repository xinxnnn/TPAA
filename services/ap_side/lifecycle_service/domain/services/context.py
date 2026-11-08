"""lifecycle-service 的共享上下文与启动自检。

★ 这里**没有** HSM、没有索引密钥、没有监管密钥。
  停运一个实例不需要任何密码学能力：它只是把 meta.json 里的状态改掉。
  找回也只是委托 agent-service 去做。

  这个"什么都没有"的状态是本服务最重要的安全属性：
  一个能被广播触发、又没有密钥的服务，即使被攻破，
  攻击者也只能改状态 —— 他偷不到任何东西，也伪造不出任何凭证。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """启动自检未通过。"""


@dataclass
class LifecycleContext:
    store: object                   # StorePort（localstore 的 AgentStore）
    agent_ops: object               # AgentOpsPort（委托 agent-service）
    clock: object                   # Clock
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []
        for name in ("store", "agent_ops", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        # 真探一次存储根：不可读会让"停运"静默失败 ——
        # 广播收到了、返回 200、实例还在跑，这是最坏的一种失败。
        if self.store is not None:
            try:
                self.store.iter_all()
            except Exception as exc:                 # noqa: BLE001
                errors.append(f"本地资产目录不可读：{exc}")

        return errors

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError(
                "lifecycle-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["LifecycleContext", "ConfigError"]
