"""TP 侧与跨域服务的落盘底座：原子写 JSON。

为什么不用数据库：
    这些服务持有的是**注册表与台账**，量小、形态固定、且必须能被人工审阅。
    一个能 `cat` 出来的 JSON 文件，在出事那天的价值远高于一个需要客户端才能查的库。
    等真的需要并发与查询，换实现即可 —— 接口只有三个方法。

为什么必须原子写：
    DID 注册表与审计链都是"写坏一条就全盘不可信"的数据。
    直接 `open(w)` 会在写一半时留下截断的文件，而进程恰好在这时被杀掉的概率
    在真机上并不低（容器被驱逐、OOM、断电）。所以走 tmp + fsync + rename：
    磁盘上任何时刻看到的都是**上一版完整内容**或**这一版完整内容**，没有中间态。

为什么这个文件里没有锁的跨进程版本：
    一服务一库（ARCHITECTURE §6），同一个库只会被一个服务进程写。
    跨进程锁要到真的多副本部署时才需要，那时该换的是存储，不是加一把文件锁。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Iterator, MutableMapping
from pathlib import Path


class StoreError(RuntimeError):
    """落盘失败。通常是目录不可写或磁盘满 —— 都属于必须让人看见的故障。"""


class JsonStore:
    """单文件 JSON 存储，原子写。

    `load()` 在文件不存在时返回 `default`，这是刻意的：
    服务第一次启动时库本来就不存在，让调用方去区分"不存在"和"空"没有意义。
    """

    def __init__(self, path: str | Path, *, default: dict | None = None) -> None:
        self.path = Path(path)
        self.default = default if default is not None else {}
        self._lock = threading.RLock()

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> dict:
        with self._lock:
            if not self.path.exists():
                return dict(self.default)
            try:
                raw = self.path.read_text(encoding="utf-8")
            except OSError as exc:
                raise StoreError(f"读取失败 {self.path}：{exc}") from exc
            if not raw.strip():
                return dict(self.default)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                # ★ 坏掉的库绝不静默重置 —— 那等于替攻击者擦掉痕迹，
                #   也让运维失去"什么时候坏的"这条线索。让它炸出来。
                raise StoreError(
                    f"{self.path} 不是合法 JSON（第 {exc.lineno} 行）—— "
                    "已停止读取，请人工确认后再决定是否重建") from exc
            if not isinstance(data, dict):
                raise StoreError(f"{self.path} 顶层应为对象，实际为 {type(data).__name__}")
            return data

    def save(self, data: dict) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_name = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self.path)
            except OSError as exc:
                # 临时文件留着，是排障的线索；不吞异常
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise StoreError(f"写入失败 {self.path}：{exc}") from exc

    def update(self, fn) -> dict:
        """读—改—写。fn 收到当前内容，返回新内容（原地改也行）。"""
        with self._lock:
            data = self.load()
            out = fn(data)
            self.save(out if out is not None else data)
            return out if out is not None else data


class JsonStoreMapping(MutableMapping):
    """A persistent mapping backed by one atomic JSON store."""

    def __init__(self, path: str | Path, *, key: str = "items") -> None:
        self.store = JsonStore(path)
        self.key = key

    def __getitem__(self, item):
        values = self.store.load().get(self.key, {})
        try:
            return values[item]
        except KeyError:
            raise KeyError(item) from None

    def __setitem__(self, item, value) -> None:
        def update(data):
            values = data.setdefault(self.key, {})
            if not isinstance(values, dict):
                raise StoreError(f"{self.store.path} 的 {self.key} 必须是 JSON 对象")
            values[item] = value
            return data

        self.store.update(update)

    def __delitem__(self, item) -> None:
        def update(data):
            values = data.setdefault(self.key, {})
            if not isinstance(values, dict):
                raise StoreError(f"{self.store.path} 的 {self.key} 必须是 JSON 对象")
            if item not in values:
                raise KeyError(item)
            del values[item]
            return data

        self.store.update(update)

    def __iter__(self) -> Iterator:
        values = self.store.load().get(self.key, {})
        if not isinstance(values, dict):
            raise StoreError(f"{self.store.path} 的 {self.key} 必须是 JSON 对象")
        return iter(tuple(values))

    def __len__(self) -> int:
        values = self.store.load().get(self.key, {})
        if not isinstance(values, dict):
            raise StoreError(f"{self.store.path} 的 {self.key} 必须是 JSON 对象")
        return len(values)


__all__ = ["JsonStore", "JsonStoreMapping", "StoreError"]
