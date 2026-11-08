"""TPAA 密码学原语层。

对外只暴露这五个能力；上层（services / runtime）一律通过 crypto/sdk 调用，
不得自行实现任何密码学运算。

    group       secp256k1 群运算（恒定时间）
    schnorr     签名 / 验签
    paillier    加法同态加密
    chameleon   变色龙哈希 + 陷门碰撞

      PublicChameleon  只有公钥的句柄（能算不能改），跨域协同传它
      ChameleonHash    持有陷门的句柄（能算也能改），仅留在本域 HSM 内

    hashchain   哈希链 HCGen
"""

from . import chameleon, group, hashchain, paillier, schnorr
from .chameleon import (
    ChameleonHash,
    ChameleonKey,
    PublicChameleon,
    TrapdoorUnavailable,
    as_public,
    require_public,
)
from .group import (
    G,
    N,
    P,
    is_on_curve,
    new_secret,
    deser_point,
    point_add,
    point_mul,
    point_neg,
    pubkey,
    ser_point,
)
from .hashchain import GENESIS, first_divergence, hash_chain, hash_chain_layers, verify_chain
from .paillier import Paillier
from .schnorr import SchnorrSig, challenge, sign, verify

__all__ = [
    "chameleon", "group", "hashchain", "paillier", "schnorr",
    "G", "N", "P", "point_add", "point_mul", "point_neg", "ser_point", "deser_point", "is_on_curve",
    "new_secret", "pubkey",
    "SchnorrSig", "sign", "verify", "challenge",
    "Paillier",
    "ChameleonHash", "ChameleonKey", "PublicChameleon", "TrapdoorUnavailable",
    "as_public", "require_public",
    "hash_chain", "hash_chain_layers", "verify_chain", "first_divergence", "GENESIS",
]
