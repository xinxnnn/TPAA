"""监管封存（CSCID）的受限对外入口（经 crypto.sdk，不接受越权直连）。

只有三个动作：
    make_supervision_key   生成监管密钥（演练 / 部署注入时调用一次）
    seal_identity          用公钥形态把 H(ID) 封成 CSCID
    open_identity          立案之后还原 H(ID)（需要完整密钥形态）

★ open_identity 只接受 SupervisionKey。公钥形态（SupervisionPublic）
  在 crypto/hsm/supervision.py 里就已经把 open 拒掉了 —— 这里不做第二次判断，
  因为类型层已经把这条路堵死，再判一次只是把同一句话说两遍。
"""

from __future__ import annotations

from ..hsm.supervision import SupervisionKey, SupervisionPublic

__all__ = ["SupervisionKey", "SupervisionPublic",
           "make_supervision_key", "supervision_public_from_n",
           "seal_identity", "open_identity"]


def make_supervision_key(*, bits: int = 2048, seed: bytes | None = None) -> SupervisionKey:
    """生成监管密钥。seed 仅用于本地测试环境重现同一密钥。"""
    return SupervisionKey(bits, seed=seed)


def supervision_public_from_n(n: int | str) -> SupervisionPublic:
    """由监管公钥的模数 n 重建公钥形态 —— 供各服务启动时从部署参数装配。

    n 是公开值，所以它可以进环境变量、进配置中心、被写进日志，都不算泄密。
    需要它的服务（did-service 要封存 H(ID)）只拿到封存能力，拿不到还原能力。
    """
    return SupervisionPublic(int(n))


def seal_identity(identity_hash: int, pub: SupervisionPublic) -> int:
    """把 H(ID) 封成 CSCID。公钥形态即可 —— 申领线上人人能封，立案后才能开。"""
    return pub.seal(identity_hash)


def open_identity(cscid: int, key: SupervisionKey) -> int:
    """还原 H(ID)。只有监管域持有完整密钥，这一步对应协议 R1。"""
    return key.open(cscid)
