"""ContentPort 的本地实现：把「内容存放在哪」这件事交给 IPFS 第五方。

★ 这一方为什么不持有密钥：
  `services/ipfs/storage_service.py` has no key fields and does not parse content.
  它拿到的永远是密文/字节，CID 由内容哈希得到。所以本适配器**只转调**，
  不在这一层做任何加解密 —— 一旦这里出现加密动作，就等于把保密性
  从"密码机制"转移到了"某台机器的实现"，威胁模型立刻失效。

★ 红线 17 的落点：
  CID 是"能直接取到内容"的地址，明文落进 localstore 就等于把内容地址写在门上。
  所以 localstore 里出现的一律是 **ECID**（由 TP 加封），CID 只在本适配器
  与 IPFS 之间流动。本适配器不缓存 CID，也不把它写进任何本地文件。
"""

from __future__ import annotations

import hashlib

from ..domain.ports import StoredContent


class LocalIpfsAdapter:
    """ContentPort 的本地实现，转调 IPFS 方提供的 `StorageService`。

    生产替换为 HTTP 网关（`/api/v0/add`、`/api/v0/cat`），签名一致。
    """

    def __init__(self, *, storage, requester: str = "agent-service") -> None:
        self._storage = storage
        self._requester = requester

    def fetch(self, cid: str) -> StoredContent:
        """按 CID 取件。每次取用都会在 IPFS 侧留痕（红线 18）。"""
        payload = self._storage.get(cid, requester=self._requester)
        if payload is None:
            raise ContentNotFound(f"IPFS 侧无此对象：{cid[:16]}…（可能已被回收）")
        # ★ 取回后**本地再算一次摘要**：不信任传输层的完整性承诺。
        #   IPFS 保证的是"按内容寻址"，但保证的是**它**那侧的实现；
        #   校验一次成本极低，换来的是"拿到的确实是这个 CID 对应的内容"。
        if _cid_of(payload) != cid:
            raise ContentCorrupted(f"内容与 CID 不符：{cid[:16]}… —— 传输或存储层被改动")
        return StoredContent(cid=cid, payload=payload)

    def put(self, payload: bytes) -> str:
        """写入，返回 CID。调用方**不得**把这个值落进 localstore。"""
        return self._storage.put(payload, requester=self._requester)


def _cid_of(payload: bytes) -> str:
    """与 IPFS 侧同算法的 CID 推导（`b` + sha256 前 59 位十六进制）。

    两边不一致就等于自检失效，所以算法写在一起、并有一条对照测试盯住。
    """
    return "b" + hashlib.sha256(payload).hexdigest()[:59]


class ContentNotFound(LookupError):
    pass


class ContentCorrupted(RuntimeError):
    pass


__all__ = ["LocalIpfsAdapter", "ContentNotFound", "ContentCorrupted"]
