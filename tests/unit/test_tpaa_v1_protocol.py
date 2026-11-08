"""tpaa_v1 协议层正向用例：G1 → G4 → D1–D6 → R1 → R2，每一步的不变量。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_protocol import A, PII, T, shared, sup_key, v1  # noqa: E402


def test_g4_wallet_holds_verified_initial_phc() -> None:
    r = shared()
    assert r.cred.af.holds(r.pending.hid)
    assert r.cred.af.af == r.pending.af.af, "G2 的 CCH 不改变 AF 取值"
    assert v1.verify_public(v1.from_jsonld(r.cred.phc), **_pk(r)) == []


def test_d5_user_recomputed_cmi_and_af() -> None:
    r = shared()
    phc1 = v1.from_jsonld(r.verified.phc1)
    assert r.verified.cmi == phc1.apm.cmi == r.arec.cmi
    assert r.verified.cred.af.holds(r.pending.hid)
    assert r.verified.cred.af.af == r.pending.af.af, "算法1 的 CCH 不改变 AF 取值"


def test_d6_did_structure_and_cdid_is_ciphertext() -> None:
    r = shared()
    parts = r.did.split(":")
    assert parts[0:2] == ["did", "wba"] and parts[3:] == ["tp.example", "ap.example"]
    phc2 = v1.from_jsonld(r.phc2)
    assert r.did not in json.dumps(r.phc2), "PHC 里只有 CDID（密文），没有明文 DID"
    assert phc2.tpm.cdid and v1.verify_public(phc2, **_pk(r)) == []
    assert [v1.from_jsonld(x).version for x in (r.cred.phc, r.verified.phc1, r.phc2)] == [1, 2, 3]


def test_af_value_constant_g1_to_d6() -> None:
    r = shared()
    afs = {r.pending.af.af, r.cred.af.af, r.verified.cred.af.af,
           v1.from_jsonld(r.phc2).tpm.af, r.trec2.af.af, r.arec.af.af}
    assert len(afs) == 1


def test_r1_reveal_with_ap_assist() -> None:
    r = shared()
    af, rf = T.tp_open_did(tp_hsm=r.p.tp, did=r.did)
    assert af == r.pending.af.af and rf == r.arec.rf
    s_ap = A.ap_assist(ap_hsm=r.p.ap, af=af, case_ok=True)
    assert T.tp_reveal(sup_key=sup_key(), rf=rf, s_ap=s_ap, rec=r.trec2) == r.pending.hid


def test_r2_recovers_pii_through_resealed_ecid() -> None:
    r = shared()
    _, rf = T.tp_open_did(tp_hsm=r.p.tp, did=r.did)
    got = T.tp_recover_pii(tp_hsm=r.p.tp, sup_key=sup_key(), rec=r.trec2, rf=rf,
                           storage=r.p.storage)
    assert got["PII"] == PII


def test_ecid_resealed_without_psk() -> None:
    """D6 的 ECID 重封走同态加法，phc-service 不需要监管私钥。"""
    r = shared()
    assert r.trec2.ecid != r.trec.ecid
    assert int(v1.from_jsonld(r.phc2).tpm.ecid, 16) == r.trec2.ecid


def test_ipfs_only_holds_ciphertext() -> None:
    r = shared()
    blobs = b"".join(r.p.storage._objects.values())                    # noqa: SLF001
    for s in (PII["ID"], PII["name"], "iris-template-demo"):
        assert s.encode() not in blobs


def _pk(r) -> dict:
    return {"tp_pk": r.p.tp.pubkey(), "ap_pk": r.p.ap.pubkey()}
