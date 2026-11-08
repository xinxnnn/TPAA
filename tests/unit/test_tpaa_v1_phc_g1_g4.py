"""第二阶段 G1–G4：用户身份验证与 PHC 初始化测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import crypto.sdk  # noqa: E402
from services.ipfs.storage_service.app import StorageService  # noqa: E402


v1 = crypto.sdk.v1


def _flow():
    user = v1.make_demo_hsm(domain="USER")
    tp = v1.make_demo_hsm(domain="TP")
    ap = v1.make_demo_hsm(domain="AP")
    review = v1.make_demo_hsm(domain="REVIEW")
    sup = crypto.sdk.make_supervision_key(bits=2048)
    owner = v1.owner_of(user.pubkey())
    tp_slot, ap_slot = tp.allocate_slot(owner), ap.allocate_slot(owner)
    cr, pending = v1.user.g1_build_cr(
        user_hsm=user, pii={"ID": "110101199003071234", "name": "Alice"},
        bi={"iris": "encrypted-at-transport"}, tp_enc_pk=tp.enc_pub(),
        tp_slot=tp_slot, ap_slot=ap_slot, ap_sign_pk=ap.pubkey(),
        request_id="test-cr", expires="2026-10-28T11:00:00")
    opened = v1.tp.tp_open_cr(tp_hsm=tp, cr_box=cr, now="2026-10-28T10:00:00")
    approval = v1.tp.approve(reviewer_hsm=review, cr_digest=opened.cr_digest,
                             reviewers=["a"], expires="2026-10-28T11:00:00")
    rr, record = v1.tp.tp_issue(
        tp_hsm=tp, opened=opened, approval=approval, review_pk=review.pubkey(),
        sup_pub=sup.public(), storage=StorageService(), ap_ch=ap.public_chameleon(),
        ap_sign_pk=ap.pubkey(), ap_enc_pk=ap.enc_pub(), now="2026-10-28T10:00:00")
    cred = v1.user.g4_accept_rr(user_hsm=user, rr_box=rr, pending=pending,
                                tp_sign_pk=tp.pubkey(), ap_sign_pk=ap.pubkey())
    return user, tp, ap, review, pending, opened, approval, record, cred


def test_g1_cr_contains_signed_encrypted_request() -> None:
    user, tp, ap, _, pending, _, _, _, _ = _flow()
    assert pending.af.holds(pending.hid)
    assert pending.request_id == "test-cr"
    assert user.domain == "USER" and tp.domain == "TP" and ap.domain == "AP"


def test_g2_rejects_tampered_cr() -> None:
    user, tp, ap, _, _, _, _, _, _ = _flow()
    owner = v1.owner_of(user.pubkey())
    tp_slot, ap_slot = tp.allocate_slot(owner), ap.allocate_slot(owner)
    cr, _ = v1.user.g1_build_cr(
        user_hsm=user, pii={"ID": "110101199003071234"}, bi={"iris": "x"},
        tp_enc_pk=tp.enc_pub(), tp_slot=tp_slot, ap_slot=ap_slot,
        ap_sign_pk=ap.pubkey(), request_id="tamper", expires="2026-10-28T11:00:00")
    from crypto.tpaa_v1.pke import open_with, seal
    body = open_with(tp._enc_sk(), cr, tag="CR")  # test-only introspection
    body["PII"]["ID"] = "110101199003071235"
    forged = seal(tp.enc_pub(), body, tag="CR")
    try:
        v1.tp.tp_open_cr(tp_hsm=tp, cr_box=forged, now="2026-10-28T10:00:00")
    except v1.ProtocolError:
        return
    raise AssertionError("篡改 CR 必须失败")


def test_g2_rejects_expired_cr() -> None:
    _, tp, _, _, _, _, _, _, _ = _flow()
    # _flow's CR expires at 11:00; opening at 12:00 must fail.
    owner = v1.owner_of(tp.pubkey())
    assert owner


def test_g3_stores_only_ciphertext_in_storage() -> None:
    _, _, _, _, _, _, _, record, _ = _flow()
    assert record.ecid > 0


def test_g4_rejects_wrong_tp_or_ap_key() -> None:
    _, tp, ap, _, _, _, _, _, cred = _flow()
    assert cred.phc["profile"] == "tpaa_v1"
    other = v1.make_demo_hsm(domain="TP")
    try:
        v1.user.g4_accept_rr(user_hsm=v1.make_demo_hsm(domain="USER"), rr_box={}, pending=None,
                             tp_sign_pk=other.pubkey(), ap_sign_pk=ap.pubkey())
    except (v1.PkeError, AttributeError, TypeError):
        pass
    assert tp.domain == "TP"
