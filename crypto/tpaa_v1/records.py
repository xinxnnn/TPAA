"""协议记录的落盘形态：dataclass ↔ JSON。

服务把 TpRecord / ApRecord / 钱包状态写进 JsonStore，读回来要还原成同一个类型。
整数一律写成 {"$int": "<hex>"} —— 这些值大多是 3072 / 4096 bit，
JSON number 在很多语言里是 float64，直接写数字会被静默截断（见 agent-service schemas.py 的同一条坑）。

★ 能落盘的类型是白名单：反序列化不按名字 import 任意类，只认下面登记过的几个。
"""

from __future__ import annotations

import dataclasses

from .engine import AfState
from .proto_ap import ApRecord
from .proto_tp import TpRecord
from .proto_user import PendingCR, VerifiedPA, WalletCred

_TYPES = {c.__name__: c for c in (AfState, TpRecord, ApRecord, PendingCR, WalletCred, VerifiedPA)}


def dump(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        name = type(obj).__name__
        if name not in _TYPES:
            raise TypeError(f"{name} 不在可落盘类型白名单里")
        return {"$type": name,
                **{f.name: dump(getattr(obj, f.name)) for f in dataclasses.fields(obj)}}
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return obj
    if isinstance(obj, int):
        return {"$int": format(obj, "x")}
    if isinstance(obj, (list, tuple)):
        return [dump(x) for x in obj]
    if isinstance(obj, dict):
        return {k: dump(v) for k, v in obj.items()}
    raise TypeError(f"不支持落盘的值：{type(obj).__name__}")


def load(data):
    if isinstance(data, dict):
        if "$int" in data:
            return int(data["$int"], 16)
        if "$type" in data:
            cls = _TYPES.get(data["$type"])
            if cls is None:
                raise TypeError(f"未知的记录类型：{data['$type']!r}")
            fields = {f.name for f in dataclasses.fields(cls)}
            kw = {k: load(v) for k, v in data.items() if k in fields}
            if "modules" in kw:                       # ApRecord.modules 是三元组列表
                kw["modules"] = [tuple(m) for m in kw["modules"]]
            return cls(**kw)
        return {k: load(v) for k, v in data.items()}
    if isinstance(data, list):
        return [load(x) for x in data]
    return data


__all__ = ["dump", "load"]
