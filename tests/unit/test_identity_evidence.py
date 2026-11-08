"""P2: an identity decision must be independently signed and bound to one CR."""

from __future__ import annotations

import copy

from crypto.sdk import v1

NOW = "2026-11-06T12:00:00"
LATER = "2026-11-07T12:00:00"


def _fixture():
    user = v1.make_demo_hsm(domain="USER")
    tp = v1.make_demo_hsm(domain="TP")
    ap = v1.make_demo_hsm(domain="AP")
    verifier = v1.make_demo_hsm(domain="IDV")
    owner = v1.owner_of(user.pubkey())
    tp_slot = tp.allocate_slot(owner)
    ap_slot = ap.allocate_slot(owner)
    hid = v1.hid_of("synthetic-person-001")
    evidence = v1.identity_evidence.issue(
        verifier_hsm=verifier, issuer="independent-idv", hid=hid,
        user_sign_pk=v1.pk_hex(user.pubkey()), tp_nonce=tp_slot[0],
        request_id="cr-test-001", method="in-person-reviewed",
        assurance_level="substantial", evidence_ref="test-case-001",
        issued_at=NOW, expires_at=LATER)
    trust = {"independent-idv": v1.pk_hex(verifier.pubkey())}
    return user, tp, ap, tp_slot, ap_slot, evidence, trust, hid


def _verify(evidence, trust, hid, *, tp_nonce=None, request_id="cr-test-001", now=NOW,
            user_sign_pk=None, min_assurance="substantial"):
    return v1.identity_evidence.verify(
        evidence, trusted_issuers=trust, min_assurance=min_assurance,
        hid=hid, user_sign_pk=user_sign_pk or evidence["body"]["userSignPk"],
        tp_nonce=tp_nonce or evidence["body"]["tpNonce"],
        request_id=request_id, now=now)


def _must_reject(fn):
    try:
        fn()
    except v1.ProtocolError:
        return
    raise AssertionError("invalid identity evidence was accepted")


def test_signed_identity_evidence_is_bound_to_encrypted_cr():
    user, tp, ap, tp_slot, ap_slot, evidence, trust, hid = _fixture()
    cr, _ = v1.user.g1_build_cr(
        user_hsm=user, pii={"ID": "synthetic-person-001"}, bi={},
        tp_enc_pk=tp.enc_pub(), tp_slot=tp_slot, ap_slot=ap_slot,
        ap_sign_pk=ap.pubkey(), request_id="cr-test-001", expires=LATER,
        identity_evidence=evidence)
    opened = v1.tp.tp_open_cr(tp_hsm=tp, cr_box=cr, now=NOW)
    assert opened.identity_evidence == evidence
    assert _verify(opened.identity_evidence, trust, opened.hid,
                   tp_nonce=opened.tp_nonce, request_id=opened.request_id,
                   user_sign_pk=opened.user_sign_pk)["assuranceLevel"] == "substantial"


def test_identity_evidence_rejects_tampering_replay_and_untrusted_issuer():
    *_, evidence, trust, hid = _fixture()
    tampered = copy.deepcopy(evidence)
    tampered["body"]["assuranceLevel"] = "high"
    _must_reject(lambda: _verify(tampered, trust, hid))
    _must_reject(lambda: _verify(evidence, {}, hid))
    _must_reject(lambda: _verify(evidence, trust, hid, request_id="other-request"))
    _must_reject(lambda: _verify(evidence, trust, hid, tp_nonce="other-slot"))
    _must_reject(lambda: _verify(evidence, trust, hid + 1))
    _must_reject(lambda: _verify(evidence, trust, hid, now=LATER))
    _must_reject(lambda: v1.identity_evidence.verify(
        None, trusted_issuers=trust, min_assurance="substantial", hid=hid,
        user_sign_pk=evidence["body"]["userSignPk"],
        tp_nonce=evidence["body"]["tpNonce"], request_id="cr-test-001", now=NOW))


def test_identity_evidence_enforces_assurance_level():
    *_, evidence, trust, hid = _fixture()
    _must_reject(lambda: _verify(evidence, trust, hid, min_assurance="high"))
