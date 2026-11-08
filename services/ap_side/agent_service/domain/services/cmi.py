"""CMI：把「用户选了什么」算成一个可被 PHC 承诺的值。

这是整套流程里最容易做错、也最容易被忽视的一环，所以单独一个模块把规则写死：

1. **顺序由平台定**，不由前端传参定。选择向量先按 (module_id, version) 归一化，
   否则同一份意图能算出两个 CMI，PHC 里的承诺就对不上了。
2. **逐层**（哈希链的中间值）必须一起存下来。只见终值无法定位「哪一层被改」，
   追溯时会退化成「整体不一致」这种没有信息量的结论。
3. **模块内容摘要参与计算**。只算「模块名+版本号」的话，模块仓库里换了代码
   CMI 依然不变 —— 那就等于什么都没承诺。
4. 计算本身**只经 crypto.sdk**（红线 2）。

关于「三处一致」：
    PHC.tpm_af 里的 AF 把 CMI 封在身份因子里，本地 cmi.json 存一份，build 里再存一份。
    三者一致才算「磁盘上的东西确实是被签发的那一份」。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import crypto.sdk


@dataclass(frozen=True)
class Layer:
    index: int
    module_id: str
    version: str
    digest: str          # 该模块内容的摘要（来自模块仓库 manifest）
    chain: str           # 累积到这一层的哈希链值（十六进制）


@dataclass(frozen=True)
class Cmi:
    value: str                     # 最终 CMI（十六进制）
    layers: tuple[Layer, ...]

    def as_record(self) -> dict:
        return {
            "cmi": self.value,
            "layers": [
                {"index": l.index, "moduleId": l.module_id, "version": l.version,
                 "digest": l.digest, "chain": l.chain}
                for l in self.layers
            ],
            "moduleDigests": [l.digest for l in self.layers],
        }


def compute_cmi(items: list[tuple[str, str, str]]) -> Cmi:
    """items: [(module_id, version, content_digest)]，未排序的原始选择。

    ★ 摘要**不走哈希链**（那是 CMI 的活，不是签名），只走 sha256 摊平；
      CMI 本身才必须走 sdk 的哈希链 —— 它是要被 PHC 承诺的值。
    """
    normalized = sorted(items, key=lambda x: (x[0], x[1]))
    if not normalized:
        raise ValueError("选择为空，无法计算 CMI")

    parts = [f"{mid}@{ver}#{dig}" for mid, ver, dig in normalized]
    chains = crypto.sdk.hash_chain_layers(parts)
    value = crypto.sdk.hash_chain(parts)

    layers = tuple(
        Layer(index=i, module_id=mid, version=ver, digest=dig, chain=chains[i].hex())
        for i, (mid, ver, dig) in enumerate(normalized)
    )
    return Cmi(value=value.hex(), layers=layers)


def digest_of(content: bytes) -> str:
    """模块内容摘要。纯存储完整性，不涉及密钥，用标准库 sha256 即可。"""
    return hashlib.sha256(content).hexdigest()


__all__ = ["Cmi", "Layer", "compute_cmi", "digest_of"]
