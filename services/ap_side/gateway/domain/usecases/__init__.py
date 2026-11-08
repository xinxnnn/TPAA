"""gateway 的用例：处理收件箱、承接吊销广播。"""

from .intake import IntakeResult, IntakeRevocationUseCase, RevocationCommand
from .outbox import DrainOutboxUseCase

__all__ = ["DrainOutboxUseCase", "IntakeRevocationUseCase", "RevocationCommand",
           "IntakeResult"]
