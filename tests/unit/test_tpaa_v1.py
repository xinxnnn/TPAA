"""tpaa_v1 正向与边界：每条对应说明书里的一个等式或一个步骤。"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_flow import HID, MODULES, OWNER, pub_keys, run, sup_key, v1  # noqa: E402

from crypto.primitives.paillier import is_probable_prime  # noqa: E402
from crypto.tpaa_v1 import cch, encoding, params  # noqa: E402

_F = None


def _flow():
    global _F
    if _F is None:
        _F = run()
    return _F


# ---------------------------------------------------------------------------
# 参数与编码
# ---------------------------------------------------------------------------


def test_params_are_safe_prime_group() -> None:
    assert params.P.bit_length() == 3072
    assert is_probable_prime(params.P, 16) and is_probable_prime(params.Q, 16)
    assert params.in_subgroup(params.G)
    assert not params.in_subgroup(params.P - 1)        # 阶为 2 的元素必须被拒


def test_encoding_is_injective_on_field_boundaries() -> None:
    e = encoding.encode
    assert e("t", "ab", "c") != e("t", "a", "bc")
    assert e("t", 1) != e("t", "1") != e("t", b"\x01")
    assert e("t", None) != e("t", "")
    assert e("TPproof", "x") != e("APproof", "x")      # 域分离
    try:
        e("t", True)
    except TypeError:
        pass
    else:
        raise AssertionError("bool 必须被拒绝")


# ---------------------------------------------------------------------------
# G1–G4：AF 等式
# ---------------------------------------------------------------------------


def test_af_constant_across_g1_g2_d4() -> None:
    f = _flow()
    assert f.af_g1.af == f.af_g2.af == f.af_d4.af, "CCH 必须保持 AF 取值不变"
    assert f.af_g1.holds(HID) and f.af_g2.holds(HID) and f.af_d4.holds(HID)
    assert f.af_g2.x_t == cch.exponent_of("IRF", f.irf)
    assert f.af_d4.x_a == cch.exponent_of("CMI", f.cmi)
    assert len({f.af_g1.r, f.af_g2.r, f.af_d4.r}) == 3


def test_af_rejects_wrong_identity() -> None:
    f = _flow()
    assert not f.af_d4.holds(HID ^ 1)


def test_rebind_refuses_inconsistent_state() -> None:
    from dataclasses import replace
    f = _flow()
    bad = replace(f.af_g1, r=f.af_g1.r + 1)
    try:
        v1.rebind_af(bad, hsm=f.tp, hid=HID, nonce=f.tp_nonce, owner=OWNER,
                     kind="IRF", value=f.irf)
    except ValueError:
        return
    raise AssertionError("AF 等式不成立时不得调用 HSM 求碰撞")


def test_rebind_requires_right_domain() -> None:
    f = _flow()
    try:
        v1.rebind_af(f.af_g1, hsm=f.ap, hid=HID, nonce=f.ap_nonce, owner=OWNER,
                     kind="IRF", value=f.irf)
    except PermissionError:
        return
    raise AssertionError("AP 不得写 IRF 指数")


# ---------------------------------------------------------------------------
# G3 / 算法1 / 算法2
# ---------------------------------------------------------------------------


def test_issue_and_algorithms_verify_publicly() -> None:
    f = _flow()
    for phc in (f.issued.phc, f.phc_d4, f.phc_d6):
        assert v1.verify_public(phc, **pub_keys(f)) == [], phc.version
    assert [p.version for p in (f.issued.phc, f.phc_d4, f.phc_d6)] == [1, 2, 3]


def test_algorithm1_keeps_apch_and_chproof() -> None:
    f = _flow()
    a, b = f.issued.phc, f.phc_d4
    assert (a.apch, a.tpch, a.chproof, a.tpproof) == (b.apch, b.tpch, b.chproof, b.tpproof)
    assert b.apm.cmi == f.cmi and b.apm.af_ref == v1.af_ref(b.tpm.af)


def test_algorithm2_keeps_tpch_and_chproof() -> None:
    f = _flow()
    a, b = f.phc_d4, f.phc_d6
    assert (a.tpch, a.apch, a.chproof, a.approof) == (b.tpch, b.apch, b.chproof, b.approof)
    assert b.tpm.cdid.startswith("did:wba:") and b.tpm.af == a.tpm.af


def test_holders_can_open_their_own_chameleon_hash() -> None:
    f = _flow()
    k = dict(**pub_keys(f), tp_ch=f.tp.public_chameleon(), ap_ch=f.ap.public_chameleon())
    assert v1.verify_holder(f.issued.phc, **k, r_tp=f.issued.r_tp,
                            r_ap=f.issued.r_ap) == []
    assert v1.verify_holder(f.phc_d4, **k, r_tp=f.issued.r_tp,
                            r_ap=f.r_ap1) == []
    assert v1.verify_holder(f.phc_d6, **k, r_tp=f.r_tp1, r_ap=f.r_ap1) == []
    assert f.issued.phc.tpch == f.phc_d4.tpch == f.phc_d6.tpch
    assert f.issued.phc.apch == f.phc_d4.apch == f.phc_d6.apch
    assert f.issued.phc.chproof == f.phc_d4.chproof == f.phc_d6.chproof
    assert f.issued.phc.tpproof == f.phc_d4.tpproof
    assert f.phc_d4.tpproof != f.phc_d6.tpproof
    assert f.issued.phc.approof != f.phc_d4.approof
    assert f.phc_d4.approof == f.phc_d6.approof
    errs = v1.verify_holder(f.phc_d6, **k, r_tp=f.issued.r_tp)
    assert "TPCH 与内容不符" in errs, "旧的 r_tp 不应打开新内容"


def test_phc_jsonld_roundtrip_and_no_randomness_fields() -> None:
    f = _flow()
    doc = v1.to_jsonld(f.phc_d6)
    back = v1.from_jsonld(json.loads(json.dumps(doc)))
    assert v1.verify_public(back, **pub_keys(f)) == []
    text = json.dumps(doc)
    for secret in (f.r_tp1, f.r_ap1, f.issued.r_tp, f.issued.r_ap, f.af_d4.r):
        assert format(secret, "x") not in text, "随机数不得进入 PHC（errata E3）"
    assert set(doc) == {"@context", "profile", "version", "ASO", "TPA", "APA", "PROOF"}
    assert doc["@context"] == v1.JSONLD_CONTEXT
    assert set(doc["ASO"]) == {"TPM", "APM"}
    assert set(doc["ASO"]["TPM"]) == {"Time", "CDID", "AF", "ECID"}
    assert set(doc["ASO"]["APM"]) == {"Time", "CMI", "AFRef"}
    assert set(doc["TPA"]) == {"TPid", "TPproof"}
    assert set(doc["APA"]) == {"APid", "APproof"}
    assert set(doc["PROOF"]) == {"TPCH", "APCH", "CHproof", "VM"}


def test_phc_fields_and_proofs_follow_g3_d4_d6_ownership():
    f = _flow()
    initial, updated_ap, final = (
        v1.to_jsonld(f.issued.phc),
        v1.to_jsonld(f.phc_d4),
        v1.to_jsonld(f.phc_d6),
    )
    tpm0 = initial["ASO"]["TPM"]
    apm0 = initial["ASO"]["APM"]
    assert set(initial) == {"@context", "profile", "version", "ASO", "TPA", "APA", "PROOF"}
    assert tpm0 == {"Time": f.issued.phc.tpm.time, "CDID": "",
                    "AF": format(f.af_g2.af, "x"), "ECID": f.issued.phc.tpm.ecid}
    assert apm0 == {"Time": "", "CMI": "", "AFRef": ""}
    assert initial["TPA"] == {"TPid": f.issued.phc.tpid.hex(),
                              "TPproof": f.issued.phc.tpproof.hex()}
    assert initial["APA"] == {"APid": f.issued.phc.apid.hex(), "APproof": ""}
    assert initial["PROOF"] == {
        "TPCH": format(f.issued.phc.tpch, "x"),
        "APCH": format(f.issued.phc.apch, "x"),
        "CHproof": f.issued.phc.chproof.hex(),
        "VM": v1.to_jsonld(f.issued.phc)["PROOF"]["VM"],
    }

    assert updated_ap["ASO"]["TPM"] == tpm0
    assert updated_ap["ASO"]["APM"] == {
        "Time": f.phc_d4.apm.time, "CMI": f.cmi,
        "AFRef": v1.af_ref(f.af_g2.af),
    }
    assert updated_ap["TPA"] == initial["TPA"]
    assert updated_ap["PROOF"] == initial["PROOF"]
    assert updated_ap["APA"]["APproof"] == f.phc_d4.approof.hex()

    assert final["ASO"]["TPM"] == {
        "Time": f.phc_d6.tpm.time, "CDID": f.phc_d6.tpm.cdid,
        "AF": format(f.af_g2.af, "x"), "ECID": f.phc_d6.tpm.ecid,
    }
    assert final["ASO"]["APM"] == updated_ap["ASO"]["APM"]
    assert final["APA"] == updated_ap["APA"]
    assert final["PROOF"] == initial["PROOF"]
    assert [initial["version"], updated_ap["version"], final["version"]] == [1, 2, 3]


def test_legacy_phc_jsonld_roundtrips_without_changing_digest():
    f = _flow()
    current = v1.to_jsonld(f.phc_d6)
    legacy = {
        "@context": "https://tpaa.example/credentials/phc/v1",
        "profile": current["profile"],
        "version": current["version"],
        "agentSelfOwned": current["ASO"],
        "tpAttestation": current["TPA"],
        "apAttestation": current["APA"],
        "proof": current["PROOF"],
    }

    decoded = v1.from_jsonld(legacy)

    assert v1.to_jsonld(decoded) == legacy
    assert v1.phc_digest(decoded) == v1.json_digest(legacy)


def test_from_jsonld_rejects_mixed_or_incomplete_phc_layout():
    f = _flow()
    doc = v1.to_jsonld(f.phc_d6)
    mixed = {**doc, "agentSelfOwned": doc["ASO"]}
    incomplete = {**doc, "ASO": {"TPM": doc["ASO"]["TPM"]}}
    for candidate in (mixed, incomplete):
        try:
            v1.from_jsonld(candidate)
        except ValueError:
            continue
        raise AssertionError("PHC 必须拒收混用或不完整的结构")


def test_from_jsonld_rejects_proto0() -> None:
    try:
        v1.from_jsonld({"profile": "tpaa_proto0"})
    except ValueError:
        return
    raise AssertionError("不同 profile 的凭证必须拒收")


# ---------------------------------------------------------------------------
# 式 8 / 9 / 6，R1 / R2
# ---------------------------------------------------------------------------


def test_hcgen_binds_identity_order_and_content() -> None:
    base = v1.hcgen(MODULES, HID)
    assert base == v1.hcgen(list(MODULES), HID)
    assert base != v1.hcgen(MODULES, HID + 1)
    assert base != v1.hcgen(list(reversed(MODULES)), HID)
    assert base != v1.hcgen([MODULES[0], ("translate", "1.0.0", "bc" * 32)], HID)


def test_r1_reveal_needs_s_ap() -> None:
    f = _flow()
    assert v1.reveal_hid(f.rf, f.s_ap, f.sup) == HID
    assert v1.reveal_hid(f.rf, 0, f.sup) != HID, "不减 s_ap 得不到 H(ID)"


def test_s_ap_is_prf_of_ap_and_af() -> None:
    f = _flow()
    assert v1.compute_s_ap(f.ap, f.af_d4.af) == f.s_ap
    assert v1.compute_s_ap(f.ap, f.af_d4.af + 1) != f.s_ap
    try:
        v1.compute_s_ap(f.tp, f.af_d4.af)
    except PermissionError:
        return
    raise AssertionError("TP 不得计算 s_ap（errata E4）")


def test_r2_ecid_two_stage() -> None:
    f = _flow()
    n = sup_key().public().n
    mask = v1.ecid_mask(f.tp, f.rf, n)
    assert v1.open_ecid(int(f.phc_d6.tpm.ecid, 16), f.sup, mask=mask) == "bafy-demo-cid"
    assert v1.open_ecid(int(f.issued.phc.tpm.ecid, 16), f.sup) == "bafy-demo-cid"


# ---------------------------------------------------------------------------
# HSM
# ---------------------------------------------------------------------------


def test_v1_hsm_pickle_drops_root() -> None:
    f = _flow()
    blob = pickle.dumps(f.ap)
    clone = pickle.loads(blob)
    assert not clone.private_key_present()
    assert f.ap._root not in blob                             # noqa: SLF001
    try:
        clone.slot_public(f.ap_nonce)
    except PermissionError:
        pass
    else:
        raise AssertionError("降级后的 HSM 不应再能派生陷门")


def test_same_root_reproduces_slots_across_restart() -> None:
    root = b"\x07" * 32
    a = v1.make_demo_hsm(domain="AP", root=root, schnorr_sk=5, chameleon_sk=7)
    nonce, pub = a.allocate_slot(OWNER)
    b = v1.make_demo_hsm(domain="AP", root=root, schnorr_sk=5, chameleon_sk=7,
                         bindings=a._bindings)                # noqa: SLF001
    assert b.slot_public(nonce) == pub
