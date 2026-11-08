"""用例层的共享上下文：把「这个服务能用到的东西」集中一处注入。

为什么这里只放一个 **AP 自己的** HSM：
    PHC 里 APCH 那一半的陷门只在 AP 手里。TP 签发时只需要 AP 的**公钥句柄**，
    所以 TP 拿不到改写权、算法1「AP 独自完成更新」才成立。
    如果这里能掏出 TP 的 HSM，这句话立刻作废 —— 因此结构上就不给。

为什么 localstore 的加封密钥也在这里：
    `index/by-identity.enc` 是全库唯一含身份映射的文件（红线 13），
    它的密钥必须是「AP 侧持有、由部署注入」，不能拿来跟 PHC 里的任何值互为推导，
    否则拿一个 ECID 就能试出索引密钥。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import crypto.sdk

from localstore import (
    AgentStore,
    IdentityIndex,
    Layout,
    ModuleRepo,
    OwnerIndex,
    StoreLayoutError,
)


class ConfigError(RuntimeError):
    """启动自检失败 —— 不允许带病启动。"""


@dataclass
class AgentServiceContext:
    layout: Layout
    modules: ModuleRepo
    agents: AgentStore
    identity_index: IdentityIndex
    owner_index: OwnerIndex
    ap_hsm: crypto.sdk.HSM
    index_key: bytes
    capability: object          # CapabilityPort
    content: object             # ContentPort
    clock: object               # Clock
    # 派生 TTL 上限、单人名下实例上限等策略参数
    policy: dict = field(default_factory=dict)

    # ---- 便捷句柄 ----
    def sealer(self):
        return self.identity_index.sealer(self.index_key)

    def opener(self):
        return self.identity_index.opener(self.index_key)

    # ---- 启动自检 ----
    def preflight(self) -> list[str]:
        """启动时逐项核对，任何一项失败都不带病启动。

        检查的都是"错了会静默出错"的东西 —— 比如索引密钥长度不对，
        运行起来不会报错，只会让所有人都找不回自己的智能体。
        """
        errors: list[str] = []

        # 1) 域必须对：拿错域 HSM，签出来的东西在 TP 眼里一律无效
        domain = getattr(self.ap_hsm, "domain", "")
        if domain != "AP":
            errors.append(f"AP 侧 HSM 的 domain 应为 'AP'，实际 {domain!r}")

        # 2) 索引密钥长度：AEAD 的密钥必须够长，短了就是自欺欺人
        if not isinstance(self.index_key, (bytes, bytearray)):
            errors.append("索引密钥必须是 bytes")
        elif len(self.index_key) < 32:
            errors.append(f"索引密钥至少 32 字节，实际 {len(self.index_key)}")

        # 3) 存储根可写、目录齐备
        try:
            self.layout.ensure_base()
        except OSError as e:
            errors.append(f"localstore 根不可用：{e}")

        # 4) 索引能解开（要么还不存在，要么解得开）
        try:
            self.identity_index.count(opener=self.opener())
        except StoreLayoutError as e:
            errors.append(f"身份索引无法解封：{e}")
        except Exception as e:                      # noqa: BLE001 - 索引层的各类损坏
            errors.append(f"身份索引不可读：{e}")

        # 5) 端口齐备
        for name in ("capability", "content", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        return errors

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError("agent-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["AgentServiceContext", "ConfigError"]
