"""软件实现的 HSM —— 纯标准库，便于审计与移植。

生产环境替换为真实 HSM / KMS（PKCS#11、云 KMS 等），接口保持不变。

设计立场（诚实但好奇 + 红线 1）：
    * 私钥**只存在于实例内部**，对外只暴露能力与公钥。
    * __getstate__ 剥离一切私钥字段，使对象被序列化 / 传输时绝不泄漏原始密钥。
    * 反序列化后对象失去陷门（collide 不可用），符合"失去 HSM 即失去签名/碰撞能力"。
"""

from __future__ import annotations

import pickle
from secrets import randbelow

from ..primitives.chameleon import ChameleonHash, ChameleonKey, PublicChameleon
from ..primitives.group import N, point_mul, ser_point
from ..primitives.schnorr import SchnorrSig, sign
from .base import HSM


class SoftHSM(HSM):
    def __init__(self, *, domain: str, schnorr_sk: int | None = None,
                 chameleon_sk: int | None = None) -> None:
        self.domain = domain
        self._schnorr_sk = schnorr_sk if schnorr_sk is not None else (randbelow(N - 1) + 1)
        self._chameleon = ChameleonKey(chameleon_sk)
        self._chameleon_hash = ChameleonHash(self._chameleon)

    # ---- 能力（不暴露私钥）----
    def pubkey(self):
        return point_mul(self._schnorr_sk % N)

    def sign(self, msg: bytes) -> SchnorrSig:
        return sign(self._schnorr_sk, msg)

    def chameleon_cpk(self):
        return self._chameleon.cpk

    def chameleon_compute(self, m: int, r: int) -> int:
        return self._chameleon_hash.compute(m, r)

    def chameleon_collide(self, commitment, new_m: int):
        return self._chameleon_hash.forge(commitment, new_m)

    def export_public_bundle(self) -> dict:
        return {
            "domain": self.domain,
            "schnorr_pubkey": ser_point(self.pubkey()).hex(),
            "chameleon_cpk": ser_point(self.chameleon_cpk()).hex(),
        }

    # ---- 红线 1：私钥不得随对象被导出 ----
    def __getstate__(self) -> dict:
        """序列化时剥离一切密钥材料。

        陷门**连同 Schnorr 私钥一起**被剥掉，但**公钥句柄保留**：
        反序列化后的对象仍能验算（compute），不能改写（forge）。
        这正是"失去 HSM 即失去签名/改写能力"应有的样子 ——
        验算是人人可做的公开动作，改写不是。
        """
        state = self.__dict__.copy()
        state.pop("_schnorr_sk", None)
        ch = state.get("_chameleon")
        if ch is not None:
            pub = PublicChameleon(ch.cpk)
            state["_chameleon"] = pub
            state["_chameleon_hash"] = pub
        return state

    def __setstate__(self, state: dict):
        self.__dict__.update(state)

    def private_key_present(self) -> bool:
        return hasattr(self, "_schnorr_sk") and self._schnorr_sk is not None
