"""HSM 适配层测试：双域隔离 + 私钥不出实例。"""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crypto.hsm import SoftHSM
from crypto.primitives.schnorr import verify


def test_tp_sign_verify_roundtrip() -> None:
    """TP 用自己的 HSM 签名，用公钥验签通过。"""
    hsm = SoftHSM(domain="TP")
    msg = b"authorize-phc"
    sig = hsm.sign(msg)
    assert verify(hsm.pubkey(), msg, sig)


def test_tp_ap_keys_independent() -> None:
    """TP 与 AP 是两套独立密钥，互不持有对方陷门。"""
    tp = SoftHSM(domain="TP")
    ap = SoftHSM(domain="AP")
    assert tp.pubkey() != ap.pubkey()
    assert tp.chameleon_cpk() != ap.chameleon_cpk()
    assert tp.domain == "TP" and ap.domain == "AP"


def test_chameleon_collide_keeps_value() -> None:
    """持有陷门的 HSM 能合法碰撞且哈希值不变（算法1 的密码学基础）。"""
    hsm = SoftHSM(domain="TP")
    m, r = 12345, 67890
    h0 = hsm.chameleon_compute(m, r)
    m2, r2 = hsm.chameleon_collide((m, r), 999)
    h1 = hsm.chameleon_compute(m2, r2)
    assert h0 == h1


def test_private_key_not_in_pickle() -> None:
    """★ 红线 1：序列化结果里不得出现任何私钥数值。"""
    hsm = SoftHSM(domain="TP")
    blob = pickle.dumps(hsm)
    assert str(hsm._schnorr_sk).encode() not in blob
    assert str(hsm._chameleon.sk).encode() not in blob


def test_deserialized_loses_trapdoor() -> None:
    """对象离开 HSM（反序列化）后失去陷门，符合"失去 HSM 即失去能力"。"""
    hsm = SoftHSM(domain="AP")
    blob = pickle.dumps(hsm)
    h2 = pickle.loads(blob)
    assert not h2.private_key_present()
    assert h2.chameleon_cpk() == hsm.chameleon_cpk()  # 公钥仍在，可 compute
