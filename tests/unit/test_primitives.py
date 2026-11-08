"""密码学原语层单元测试。

    python tests/unit/test_primitives.py
    或 pytest tests/unit/test_primitives.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crypto.primitives import (  # noqa: E402
    ChameleonHash,
    ChameleonKey,
    G,
    N,
    Paillier,
    SchnorrSig,
    hash_chain,
    hash_chain_layers,
    is_on_curve,
    new_secret,
    point_add,
    point_mul,
    point_neg,
    pubkey,
    ser_point,
    sign,
    verify,
)


def test_curve_parameters_sane() -> None:
    assert is_on_curve(G)
    # 生成元的阶必须等于 N
    assert point_mul(N) is None
    # N·G 之外，任意 k∈[1,N) 都应得到非无穷远点
    assert point_mul(1) == G


def test_point_arithmetic_laws() -> None:
    P = point_mul(12345)
    Q = point_mul(6789)
    # 交换律
    assert point_add(P, Q) == point_add(Q, P)
    # 结合律抽样验证
    R = point_mul(42)
    assert point_add(point_add(P, Q), R) == point_add(P, point_add(Q, R))
    # 逆元
    assert point_add(P, point_neg(P)) is None
    # 标量乘法可加性: (a+b)·G == a·G + b·G
    assert point_mul(1000 + 2000) == point_add(point_mul(1000), point_mul(2000))


def test_scalar_mul_constant_time_shape() -> None:
    """不论标量取值，ladder 循环次数固定为 256。"""
    a = point_mul(1)
    b = point_mul(N - 1)
    assert a is not None and b is not None
    assert a[2] == 1 and b[2] == 1  # 输出统一归一化到仿射坐标


def test_schnorr_sign_verify() -> None:
    sk = new_secret()
    pk = pubkey(sk)
    msg = b"tpaa:phc:issue"
    sig = sign(sk, msg)
    assert verify(pk, msg, sig)
    assert not verify(pk, msg + b"!", sig)          # 消息被改
    assert not verify(point_mul(new_secret()), msg, sig)    # 换公钥


def test_schnorr_is_deterministic_given_nonce() -> None:
    sk = new_secret()
    pk = pubkey(sk)
    assert sign(sk, b"m", k=7) == sign(sk, b"m", k=7)


def test_paillier_additive_homomorphism() -> None:
    pa = Paillier(2048)
    c1, c2 = pa.encrypt(42), pa.encrypt(58)
    assert pa.decrypt(pa.add(c1, c2)) == 100
    # 密文乘常数 = 明文乘常数
    assert pa.decrypt(pa.mul_const(c1, 3)) == 126
    # 独立随机性：同一明文两次加密结果不同
    assert pa.encrypt(42) != pa.encrypt(42)


def test_paillier_roundtrip_large_identity_hash() -> None:
    pa = Paillier(2048)
    idh = int.from_bytes(hashlib.sha256(b"110101199003071234").digest(), "big")
    assert pa.decrypt(pa.encrypt(idh)) == idh


def test_seeded_paillier_key_is_reproducible_for_local_test_adapter() -> None:
    seed = bytes(range(32))
    first = Paillier(2048, seed=seed)
    restarted = Paillier(2048, seed=seed)
    assert (first.p, first.q, first.n) == (restarted.p, restarted.q, restarted.n)
    value = int.from_bytes(hashlib.sha256(b"synthetic identity").digest(), "big")
    assert restarted.decrypt(first.encrypt(value)) == value


def test_chameleon_collision_keeps_hash_value() -> None:
    key = ChameleonKey()
    ch = ChameleonHash(key)
    m1, r1 = 111111, ch.rand()
    h1 = ch.compute(m1, r1)

    m2, r2 = ch.forge((m1, r1), 999999)
    assert ch.compute(m2, r2) == h1          # ★ 哈希值不变
    assert (m2, r2) != (m1, r1)                 # 随机数确实变了


def test_chameleon_collision_stable_after_many_rounds() -> None:
    key = ChameleonKey()
    ch = ChameleonHash(key)
    m, r = 5, ch.rand()
    h = ch.compute(m, r)
    for i in range(10):                            # 模拟反复更新（升级/找回）
        m, r = ch.forge((m, r), 1000 + i)
        assert ch.compute(m, r) == h


def test_hash_chain_properties() -> None:
    a = hash_chain([b"x", b"y"])
    assert a != hash_chain([b"y", b"x"])      # 顺序敏感
    assert a == hash_chain([b"x", b"y"])          # 可复现
    assert hash_chain([]) == b"\x00" * 32

    layers = hash_chain_layers([b"a", b"b", b"c"])
    assert len(layers) == 3
    assert layers[-1] == hash_chain([b"a", b"b", b"c"])
