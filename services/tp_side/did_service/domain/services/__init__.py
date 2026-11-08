"""did-service 的域内服务：共享上下文与启动自检。"""

from .context import ConfigError, DidContext

__all__ = ["DidContext", "ConfigError"]
