"""did-service 的端口。

这个服务对外的依赖少得反常 —— 只有一个时钟和一个监管公钥句柄。
这是刻意的：**号码簿不该依赖任何会说话的东西**。
它不需要问 phc-service「这个 DID 是你签的吗」，因为 DID 是 phc-service 送来登记的，
送来的动作本身就是声明；它也不需要问 IPFS 任何事，`ecid_ref` 只是一个引用字符串。

依赖越少，它就越能在追溯时被信任 —— 追溯恰恰是系统最脆弱的时刻：
那时各服务可能正在互相指责，而这张表必须仍然说得清楚"谁的父亲是谁"。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str:
        """ISO 8601 时间戳（秒级）。"""
        ...


@runtime_checkable
class RegistryPort(Protocol):
    """注册表的读写契约。

    为什么域层要为自己依赖的存储再声明一次端口：
    今天是 JSON 文件，明天可能是 TP 区里的真库。用例不该知道是哪种，
    否则"换库"就变成了"改业务"。
    """

    def get(self, did: str): ...
    def put(self, record) -> None: ...
    def all(self) -> dict: ...
    def self_check(self) -> None: ...


__all__ = ["Clock", "RegistryPort"]
