"""生命周期服务的领域模型：吊销通知与停运结果。

★ 这里没有"删除"。停运只有一种形态：**冻结**。
  冻结保住现场（文件全在、状态可查、可人工解冻），删除把现场也一起带走。
  追溯时最需要的恰恰是"它当时是什么样"。

★ 为什么 `already` 要单独记：
  广播是"至少一次"的语义（网络重试、人工重发都会重复送）。
  第二次收到同一条吊销，正确的反应是"已经在停运状态"，而不是报错 ——
  否则运维会在慌乱中看到一堆红色，然后开始怀疑吊销到底生效了没有。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RevocationNotice:
    root_did: str
    revoked: list[str] = field(default_factory=list)
    case_ref: str = ""
    reason: str = ""


@dataclass(frozen=True)
class StopResult:
    root_did: str
    stopped: list[str] = field(default_factory=list)      # 本次被冻结的
    already: list[str] = field(default_factory=list)      # 本来就是停运态
    not_local: list[str] = field(default_factory=list)    # 本机没有这个实例
    case_ref: str = ""

    def to_json(self) -> dict:
        return {"rootDid": self.root_did, "stopped": self.stopped,
                "already": self.already, "notLocal": self.not_local,
                "caseRef": self.case_ref}


class LifecycleError(RuntimeError):
    """生命周期动作被拒。"""


__all__ = ["RevocationNotice", "StopResult", "LifecycleError"]
