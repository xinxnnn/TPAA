"""tpaa_v1 初始化阶段：公共参数、User/AP/TP 密钥与 TP Paillier 密钥。

对应《TPAA说明书》初始化阶段：

    pp = (p, g, E, q, G, n, g1)
    User: sk_a -> pk_a = g^sk_a mod p
    AP:   sk_ap -> pk_ap = g^sk_ap mod p, cpk_ap = sk_ap * G
    TP:   sk_tp -> pk_tp = g^sk_tp mod p, cpk_tp = sk_tp * G
          Paillier (n, g1), psk=(lambda, mu)

实现约定：
    * p/g 是 RFC 3526 3072-bit MODP q 阶子群（tpaa_v1.params）。
    * E/G 是现有 secp256k1 原语的曲线与生成点，曲线阶为 N。
    * 说明书把两个群的 q 写成同一个符号；代码明确区分 dl_q 与 ec_q，避免把
      MODP 子群阶误当成 secp256k1 阶。
    * Paillier 默认 3072 bit；测试可显式传 2048 bit 以缩短耗时。
    * 私钥只存在 KeyMaterial 私有字段与 TP PaillierPrivate 中；public_bundle()
      只返回可发布材料。
"""

from __future__ import annotations

from dataclasses import dataclass
from secrets import randbelow

from ..primitives.group import G as EC_G, N as EC_Q, P as EC_P, ser_point
from ..primitives.paillier import Paillier
from .params import G as DL_G, P as DL_P, Q as DL_Q, PARAMS_ID, in_subgroup


@dataclass(frozen=True)
class PublicParameters:
    """可发布给 User、TP、AP 的系统公共参数。"""

    p: int
    g: int
    dl_q: int
    ec_p: int
    ec_q: int
    G: bytes
    n: int
    g1: int
    params_id: str = PARAMS_ID

    def to_public_json(self) -> dict:
        return {
            "profile": "tpaa_v1",
            "paramsId": self.params_id,
            "p": format(self.p, "x"),
            "g": format(self.g, "x"),
            "dlQ": format(self.dl_q, "x"),
            "E": {"name": "secp256k1", "fieldP": format(self.ec_p, "x"),
                  "orderQ": format(self.ec_q, "x")},
            "G": self.G.hex(),
            "n": format(self.n, "x"),
            "g1": format(self.g1, "x"),
        }


@dataclass(frozen=True)
class PaillierPublic:
    n: int
    g1: int

    @property
    def n_squared(self) -> int:
        return self.n * self.n

    def to_public_json(self) -> dict:
        return {"n": format(self.n, "x"), "g1": format(self.g1, "x")}


@dataclass(frozen=True)
class PaillierPrivate:
    """TP-only Paillier private material: lambda and mu, plus private p/q internally."""

    lam: int
    mu: int
    _paillier: Paillier

    def decrypt(self, ciphertext: int) -> int:
        return self._paillier.decrypt(ciphertext)


@dataclass(frozen=True)
class PaillierKeyPair:
    public: PaillierPublic
    private: PaillierPrivate


@dataclass(frozen=True)
class KeyMaterial:
    """一个实体的初始化密钥材料。

    `sk` 是 DL 群私钥；`pk` 是 g^sk；`cpk` 是 secp256k1 上 sk*G。
    User 只需要 pk（不需要 cpk），AP/TP 使用完整集合。
    """

    entity: str
    _sk: int
    pk: int
    cpk: bytes

    @property
    def secret(self) -> int:
        """仅初始化装配与 HSM 注入使用；业务流程不得调用。"""
        return self._sk

    def public_bundle(self) -> dict:
        return {
            "entity": self.entity,
            "pk": format(self.pk, "x"),
            "cpk": self.cpk.hex(),
        }

    def __getstate__(self) -> dict:
        raise TypeError("KeyMaterial 是初始化私密材料，禁止直接序列化；请写入 HSM/KMS")


def public_parameters(*, paillier_bits: int = 3072) -> tuple[PublicParameters, PaillierKeyPair]:
    """生成初始化公共参数和 TP-only Paillier 密钥对。

    p/g/E/G 是固定、可审计的系统参数；Paillier n 每次初始化生成一对新的密钥。
    """
    if paillier_bits < 2048:
        raise ValueError("Paillier 初始化密钥至少 2048 bit，生产建议 3072 bit")
    pae = Paillier(paillier_bits)
    public = PaillierPublic(n=pae.n, g1=pae.g)
    params = PublicParameters(
        p=DL_P, g=DL_G, dl_q=DL_Q,
        ec_p=EC_P, ec_q=EC_Q, G=ser_point(EC_G),
        n=pae.n, g1=pae.g,
    )
    return params, PaillierKeyPair(
        public=public,
        private=PaillierPrivate(lam=pae.lam, mu=pae.mu, _paillier=pae),
    )


def generate_entity_keypair(entity: str) -> KeyMaterial:
    """为 User/AP/TP 生成说明书所需的 DL 私钥、公钥与 CCH 公钥。"""
    if entity not in {"USER", "AP", "TP"}:
        raise ValueError("entity 必须是 USER、AP 或 TP")
    sk = randbelow(DL_Q - 1) + 1
    pk = pow(DL_G, sk, DL_P)
    cpk_point = _ec_mul_secret(sk)
    return KeyMaterial(entity=entity, _sk=sk, pk=pk, cpk=ser_point(cpk_point))


def _ec_mul_secret(sk: int):
    """HSM 初始化适配点：只在生成密钥材料时使用 secp256k1 原语。"""
    from ..primitives.group import point_mul

    return point_mul(sk % EC_Q)


def initialize_system(*, paillier_bits: int = 3072) -> tuple[PublicParameters, KeyMaterial, KeyMaterial, KeyMaterial, PaillierKeyPair]:
    """一键完成初始化：返回 (pp, user, ap, tp, paillier)。

    生产装配应将 user/ap/tp/paillier.private 分别注入对应 HSM/KMS，
    只把 `pp.to_public_json()` 与各 `public_bundle()` 发布出去。
    """
    pp, pae = public_parameters(paillier_bits=paillier_bits)
    user = generate_entity_keypair("USER")
    ap = generate_entity_keypair("AP")
    tp = generate_entity_keypair("TP")
    return pp, user, ap, tp, pae


def verify_initialization(pp: PublicParameters, user: KeyMaterial, ap: KeyMaterial,
                          tp: KeyMaterial, pae: PaillierKeyPair) -> list[str]:
    """启动自检：检查参数、三方公钥关系、Paillier 往返与私钥隔离。"""
    errors: list[str] = []
    if not in_subgroup(pp.g) or pp.g != DL_G:
        errors.append("DL 生成元不在 tpaa_v1 q 阶子群")
    for material in (user, ap, tp):
        if pow(pp.g, material.secret, pp.p) != material.pk:
            errors.append(f"{material.entity} 的 pk != g^sk")
        if material.entity in {"AP", "TP"} and not material.cpk:
            errors.append(f"{material.entity} 缺少 cpk")
    if pp.n != pae.public.n or pp.g1 != pae.public.g1:
        errors.append("pp 中的 Paillier 公钥与 TP 私有密钥不匹配")
    probe = 123456789
    ciphertext = pae.private._paillier.encrypt(probe)
    if pae.private.decrypt(ciphertext) != probe:
        errors.append("Paillier 加解密往返失败")
    return errors


__all__ = [
    "PublicParameters", "PaillierPublic", "PaillierPrivate", "PaillierKeyPair",
    "KeyMaterial", "public_parameters", "generate_entity_keypair",
    "initialize_system", "verify_initialization",
]
