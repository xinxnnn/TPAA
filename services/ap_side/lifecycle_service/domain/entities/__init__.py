"""lifecycle-service 的领域实体。"""

from .lifecycle import LifecycleError, RevocationNotice, StopResult

__all__ = ["RevocationNotice", "StopResult", "LifecycleError"]
