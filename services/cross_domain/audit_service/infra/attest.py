"""子体 PHC 存证的去处。

存的是 PHC 的 JSON 原文 —— 因为它**本来就是公开交换形态**：
    PHC 要跨域传给 AP、要写进 build 的 integrity.json、要被 runtime 读取。
    一个到处传的东西不存在"存下来就泄漏"的问题，而"存不下原文"才是真问题：
    子体销毁之后，取证时要看的正是它当初被签发成什么样。

★ 必须与 localstore 分开：localstore 是 AP 侧资产、由 AP 写；
 这里是审计侧，独立于任何一方。两边各自留一份，才能互相印证。
"""

from __future__ import annotations

import threading
from pathlib import Path

from services.shared.store import JsonStore


class PhcAttachments:
    def __init__(self, path: str | Path) -> None:
        self.store = JsonStore(path, default={"attachments": {}})
        self._lock = threading.RLock()

    def put(self, *, did: str, phc_json: dict) -> str:
        with self._lock:
            issued: dict = {}

            def _fn(data: dict) -> dict:
                atts = data.setdefault("attachments", {})
                att_id = f"att-{did.replace(':', '_')}-{len(atts) + 1:04d}"
                atts[att_id] = {"did": did, "phc": phc_json}
                issued["id"] = att_id
                return data

            self.store.update(_fn)
            return issued["id"]

    def get(self, att_id: str) -> dict | None:
        return self.store.load().get("attachments", {}).get(att_id)

    def count(self) -> int:
        return len(self.store.load().get("attachments", {}))

    def self_check(self) -> None:
        if not isinstance(self.store.load().get("attachments", {}), dict):
            raise RuntimeError("存证库结构损坏：attachments 应为对象")


__all__ = ["PhcAttachments"]
