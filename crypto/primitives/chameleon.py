"""变色龙哈希 CH / CCH —— 整套方案的枢纽。

构造（在 secp256k1 群上）：
    CH(m; r) = H( m·G + r·cpk )
    其中 cpk = t·G，t 为陷门。

碰撞（需要陷门 t）：
    求 r' 使得 m·G + r·cpk == m'·G + r'·cpk
      ⇒ (m − m')G + (r − r')·t·G = O
      ⇒ (m − m') + (r − r')·t ≡ 0  (mod N)
      ⇒ r' = r + (m − m')·t⁻¹  (mod N)

这个性质是本方案的关键：TP 签名之后，AP 仍能合法改写 PHC 的
ASO.APM 内容，而 TP 的签名继续有效 —— 因为 APCH 的取值恒定不变。

★ 本模块有两个类型，区分不是为了好看，而是为了**双域隔离**：

    PublicChameleon   只有 cpk：能算哈希、能选随机数，**不能**求碰撞
    ChameleonHash     持有陷门：上面那些都能，外加 forge

TP 签发 PHC 时必须为 AP 预留 APCH 的位置，而 APCH 用的是 **AP 的**变色龙公钥。
TP 只需要能"算出"这个值，永远不需要能"改写"它。若把含陷门的对象直接交给 TP，
等于顺手把 AP 的改写权也送了出去 —— 那算法1 的"AP 独自完成"就名存实亡了。
"""

from __future__ import annotations

import hashlib
from secrets import randbelow

from .group import N, Point, point_add, point_mul, ser_point


class TrapdoorUnavailable(RuntimeError):
    """试图在只有公钥的句柄上求碰撞 —— 说明跨域时传错了对象。"""


class PublicChameleon:
    """只持有变色龙**公钥**的句柄。

    能：compute / rand（这两个只需要 cpk，任何人都能做）
    不能：forge —— 调用直接抛 TrapdoorUnavailable

    跨域协同一律传这个类型。持有者即使拿到了它，也改写不了任何东西。
    """

    def __init__(self, cpk: Point) -> None:
        self.cpk = cpk

    def has_trapdoor(self) -> bool:
        return False

    def compute(self, m: int, r: int) -> int:
        pt = point_add(point_mul(m), point_mul(r, self.cpk))
        return int.from_bytes(hashlib.sha256(ser_point(pt)).digest(), "big")

    def rand(self) -> int:
        return randbelow(N - 1) + 1

    def forge(self, commitment: tuple[int, int], new_m: int) -> tuple[int, int]:
        raise TrapdoorUnavailable(
            "本句柄只有变色龙公钥、没有陷门，无法求碰撞。"
            "跨域协同请传 PublicChameleon；真正需要改写内容的一方，请走自己的 HSM。"
        )


def as_public(handle) -> PublicChameleon:
    """把任意变色龙句柄降级成只有公钥的形态。

    派生与校验都是公开动作 —— 只需要"算得出值"，不需要"改写得了内容"。
    所以进来什么都先降级：哪怕调用方误把含陷门的 `ChameleonHash` 塞了进来，
    降级后这个作用域里也不存在陷门，自然也就不存在顺手 forge 一下的可能。

    这是给引擎用的收口助手，不是安全措施的替代品 —— 真正的防线仍然是
    guard R4（forge 只允许出现在白名单文件）。
    """
    cpk = getattr(handle, "cpk", None)
    if cpk is None:
        raise TypeError(
            f"期望变色龙句柄（有 cpk 属性），实际得到 {type(handle).__name__}。"
            "跨域协同请传 PublicChameleon 或 HSM.public_chameleon()。"
        )
    if getattr(handle, "has_trapdoor", None) is not None and not handle.has_trapdoor():
        return handle
    return PublicChameleon(cpk)


def require_public(handle, who: str):
    """写进凭证的跨域句柄必须是**无陷门**的那一份 —— 否则当场拒绝。

    与 as_public 的分工：
        as_public        只读动作（校验 / 派生）用，降级即可：反正只会 compute
        require_public   构造动作（签发）用，必须拒绝：这一步会把句柄写进凭证，
                         带着陷门过来 = 把对方的改写权一起交给了构造方

    ★ 宁可报错也不要静默降级：签发这种地方，悄悄把陷门降级掉，
      调用方会以为自己传对了，而真正被绕过的那条红线没人再看得见。
    """
    if getattr(handle, "cpk", None) is None:
        raise TypeError(
            f"{who} 需要一个变色龙句柄（有 cpk 属性），实际得到 {type(handle).__name__}。"
            "跨域协同请传对方 HSM.public_chameleon()。"
        )
    if callable(getattr(handle, "has_trapdoor", None)) and handle.has_trapdoor():
        raise PermissionError(
            f"红线 1：{who} 收到的是**含陷门**的句柄。跨域协同一律传 "
            "hsm.public_chameleon() —— 只有公钥、算得出值却改不了内容；"
            "把陷门带过来，等于顺手把对方的改写权也交了出去。"
        )
    return handle


class ChameleonKey:
    """陷门持有方的密钥对：cpk = sk · G。"""

    def __init__(self, sk: int | None = None) -> None:
        self.sk = sk if sk is not None else (randbelow(N - 1) + 1)
        self.cpk = point_mul(self.sk)


class ChameleonHash(PublicChameleon):
    """陷门持有方的完整句柄。

    forge 是本类唯一需要陷门的动作 —— 也因此是整个密码层最敏感的一个方法，
    crypto/guard 的 R4 规则把它的出现范围钉死在本文件与 hsm/soft.py 之内。
    """

    def __init__(self, key: ChameleonKey) -> None:
        super().__init__(key.cpk)
        self._key = key

    def has_trapdoor(self) -> bool:
        return True

    def forge(self, commitment: tuple[int, int], new_m: int) -> tuple[int, int]:
        """给定旧承诺 (m, r)，求新的 (m', r')，保持哈希值不变。"""
        m, r = commitment
        t_inv = pow(self._key.sk % N, -1, N)
        new_r = (r + (m - new_m) * t_inv) % N
        return new_m, new_r
