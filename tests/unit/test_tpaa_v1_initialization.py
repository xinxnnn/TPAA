"""tpaa_v1 初始化阶段的单元测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import crypto.sdk  # noqa: E402


def test_initialization_generates_public_parameters_and_three_entities() -> None:
    pp, user, ap, tp, pae = crypto.sdk.v1.initialization.initialize_system(paillier_bits=2048)
    assert pp.p.bit_length() == 3072
    assert pp.g == 4 and pp.dl_q.bit_length() == 3071
    assert pp.ec_q.bit_length() == 256
    assert user.entity == "USER" and ap.entity == "AP" and tp.entity == "TP"
    assert user.pk != ap.pk != tp.pk
    assert ap.cpk and tp.cpk
    assert pp.n == pae.public.n and pp.g1 == pae.public.g1


def test_initialization_public_bundle_excludes_secret_scalars() -> None:
    _, user, ap, tp, _ = crypto.sdk.v1.initialization.initialize_system(paillier_bits=2048)
    for material in (user, ap, tp):
        bundle = material.public_bundle()
        assert set(bundle) == {"entity", "pk", "cpk"}
        assert "sk" not in json.dumps(bundle).lower()


def test_initialization_self_check_and_paillier_equation() -> None:
    pp, user, ap, tp, pae = crypto.sdk.v1.initialization.initialize_system(paillier_bits=2048)
    assert crypto.sdk.v1.initialization.verify_initialization(pp, user, ap, tp, pae) == []
    m = 987654321
    c = pae.private._paillier.encrypt(m)
    assert pae.private.decrypt(c) == m
    assert c != m


def test_initialization_rejects_bad_paillier_size() -> None:
    try:
        crypto.sdk.v1.initialization.initialize_system(paillier_bits=1024)
    except ValueError as exc:
        assert "2048" in str(exc)
    else:
        raise AssertionError("Paillier 1024 bit 应被拒绝")


def test_initialization_secret_material_is_not_pickleable() -> None:
    import pickle

    _, user, _, _, _ = crypto.sdk.v1.initialization.initialize_system(paillier_bits=2048)
    try:
        pickle.dumps(user)
    except TypeError:
        return
    raise AssertionError("初始化密钥材料不得直接序列化")
