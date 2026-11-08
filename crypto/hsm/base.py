"""HSM 抽象接口。

红线 1：本层是**唯一**允许接触密钥材料的地方。
HSM 把"私钥"关进一个实例内部，对外只暴露**能力**（签名、变色龙碰撞），
而不是**原材料**。上层（phc / derivation / backend）未来只应持有 HSM 句柄，
而不是原始密钥——这样"密钥只在 HSM 内"才成为可强制的架构事实。

双域隔离：TP 与 AP 各自持有**独立**的 Schnorr 私钥与变色龙陷门，
彼此不持有对方的陷门（算法1 的枢纽：AP 用自己的陷门合法碰撞，TP 不参与）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..primitives.group import Point
from ..primitives.chameleon import PublicChameleon
from ..primitives.schnorr import SchnorrSig


class HSM(ABC):
    domain: str  # "TP" 或 "AP"，用于审计与越权检查（红线 1）

    @abstractmethod
    def pubkey(self) -> Point:
        """Schnorr 公钥（用于验签）。"""

    @abstractmethod
    def sign(self, msg: bytes) -> SchnorrSig:
        """用本实例的私钥对消息签名。私钥永不离开实例。"""

    @abstractmethod
    def chameleon_cpk(self) -> Point:
        """变色龙公钥（供对方计算承诺）。"""

    def public_chameleon(self) -> PublicChameleon:
        """对外**只能**给出无陷门的句柄 —— 跨域协同就传它。

        刻意做成具体方法而不是抽象方法：任何 HSM 子类自动继承，
        没有哪个子类能自行决定"这次要不要顺手把陷门也交出去"（红线 1）。
        """
        return PublicChameleon(self.chameleon_cpk())

    @abstractmethod
    def chameleon_compute(self, m: int, r: int) -> int:
        """计算变色龙哈希 CH(m; r)。"""

    @abstractmethod
    def chameleon_collide(self, commitment, new_m: int):
        """用陷门求碰撞 (m', r')，保持哈希值不变。仅本域持有陷门。"""

    @abstractmethod
    def export_public_bundle(self) -> dict:
        """导出公钥材料（不含任何私钥），供跨域协同。"""
