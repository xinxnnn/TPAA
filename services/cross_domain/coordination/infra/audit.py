"""审计归档适配器。

三种可用形态，按部署方式选：

    CallbackAudit   同进程内直连 audit-service 的用例（本地演练 / 单体部署）
    HttpAudit       HTTP 调 audit-service（分区部署）
    MemoryAudit     只留内存（**仅测试**，重启即丢）

★ `probe()` 这个方法的由来：
    启动自检如果只判断"audit 不是 None"，那就等于没检查 ——
    一个指向了错地址的 HttpAudit 同样不是 None，然后它在每次协查时静默丢记录。
    协查丢记录不像丢数据那么刺眼，但它会让取证包在关键时刻缺一环。
    所以要求每个实现都能被真的探一次。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class MemoryAudit:
    """只留内存。⚠️ 仅测试：重启即丢，绝不可用于真实协查。"""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        rec = {"seq": len(self.entries) + 1, "kind": kind,
               "subject": subject, "payload": dict(payload)}
        self.entries.append(rec)
        return f"mem-{rec['seq']}"

    def probe(self) -> tuple[bool, str]:
        return True, "memory"

    def of_kind(self, kind: str) -> list[dict]:
        return [e for e in self.entries if e["kind"] == kind]


@dataclass
class CallbackAudit:
    """把 append 直接转给一个可调用对象（例如 audit-service 的 RecordUseCase）。

    ★ 它不做异常吞噬：审计写不进去就该让协查失败。
      一条没被记账的协查，事后的说服力是零 —— 那还不如当场失败。
    """

    record: object
    _count: int = field(default=0, init=False)

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        out = self.record(kind=kind, subject=subject, payload=payload)
        self._count += 1
        return getattr(out, "entry_id", str(out))

    def probe(self) -> tuple[bool, str]:
        return True, "callback"


class NotImplementedAudit:
    """显式的"没有审计"。

    保留这个类是为了让"不接审计"变成一个**要写出来的决定**，
    而不是一个被忘记的默认值。启动自检会因为 probe 失败而拒绝带病启动。
    """

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        raise RuntimeError("未接入审计归档：协查不可在没有留痕的情况下进行")

    def probe(self) -> tuple[bool, str]:
        return False, "未配置审计归档（NotImplementedAudit）"


__all__ = ["MemoryAudit", "CallbackAudit", "NotImplementedAudit"]
