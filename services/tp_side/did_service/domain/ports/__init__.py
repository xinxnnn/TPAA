"""did-service 的端口：时钟与注册表读写契约。"""

from .contracts import Clock, RegistryPort

__all__ = ["Clock", "RegistryPort"]
