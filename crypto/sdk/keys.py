"""哈希链与公钥句柄的受限对外入口。

为什么这两样要进 sdk：
    业务层要算 CMI（哈希链 HCGen），要拿 APCH 做「三方一致」的复算，
    这些都是**必需的合法动作**，不该逼业务层绕过 sdk 去 import 原语层（红线 2）。
    但业务层只需要「算值」和「序列化公钥」，不需要陷门 ——
    所以这里只给 `hash_chain*`、`as_public`、`ser_point`、`public_from_hex`，
    **一律不给** ChameleonHash 这种能改写的对象。
"""

from __future__ import annotations

from ..primitives import as_public, ser_point
from ..primitives.chameleon import PublicChameleon
from ..primitives.group import deser_point
from ..primitives.hashchain import first_divergence, hash_chain, hash_chain_layers

__all__ = [
    "hash_chain", "hash_chain_layers", "first_divergence",
    "as_public", "ser_point", "point_from_bytes", "public_from_cpk",
    "public_from_hex",
]


def point_from_bytes(data: bytes):
    """33 字节压缩点 → 内部点（可参与运算的形态）。

    ★ 为什么需要这个入口：
      线路上的公钥是 33 字节压缩串，而 `point_mul` 之类只吃内部点。
      两者混用不会报错，只会算出完全错误的哈希值 —— 表现出来是"验签失败"，
      现场极难区分是"被篡改"还是"传错了形态"。所以把它们做成两个名字：
      **字节形态走 `public_from_hex`，点形态走 `point_from_bytes`**，看一眼调用处就知道。
    """
    return deser_point(bytes(data))


def public_from_cpk(cpk) -> PublicChameleon:
    """由公钥点还原一个只能算、不能改的句柄。

    跨域拿到的永远只是 cpk（一串点坐标），业务层要用它复算 APCH 时走这里，
    而不是自己 new 一个含陷门的对象 —— 后者根本造不出来，也不该造。

    ★ cpk 必须是**点形态**（`point_from_bytes(bytes)` 的产物）。
      传 33 字节压缩串进来会在运算处抛 ValueError，而不是静默算错。
    """
    return PublicChameleon(cpk)


def public_from_hex(cpk_hex: str) -> PublicChameleon:
    """同上，但入参是线路上传过来的十六进制点（跨服务时的实际形态）。"""
    return PublicChameleon(deser_point(bytes.fromhex(cpk_hex)))
