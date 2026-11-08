"""lifecycle-service 的域内服务：上下文与启动自检。"""

from .context import ConfigError, LifecycleContext

__all__ = ["LifecycleContext", "ConfigError"]
