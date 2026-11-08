"""P2: identity-service must fail closed outside the local test adapter."""

from __future__ import annotations

import pytest

from crypto.sdk import v1
from services.shared.v1_http import FixedClock
from services.tp_side.identity_service.domain.usecases.intake import IdentityIntake
from services.tp_side.identity_service.infra.wiring import IdentityEvidencePolicy, build_context


def _cr(*, user, tp, ap, tp_slot, ap_slot, evidence=None):
    return v1.user.g1_build_cr(
        user_hsm=user, pii={"ID": "synthetic-person-001"}, bi={},
        tp_enc_pk=tp.enc_pub(), tp_slot=tp_slot, ap_slot=ap_slot,
        ap_sign_pk=ap.pubkey(), request_id="cr-evidence-001",
        expires="2026-11-08T12:00:00", identity_evidence=evidence)[0]


def test_formal_identity_service_requires_trust_policy(tmp_path):
    tp = v1.make_demo_hsm(domain="TP")
    with pytest.raises(RuntimeError, match="身份核验策略"):
        build_context(tp_hsm=tp, db_path=str(tmp_path / "identity.json"))


def test_formal_intake_requires_valid_evidence_again_at_issue(tmp_path):
    clock = FixedClock("2026-11-06T12:00:00")
    user = v1.make_demo_hsm(domain="USER")
    tp = v1.make_demo_hsm(domain="TP")
    ap = v1.make_demo_hsm(domain="AP")
    idv = v1.make_demo_hsm(domain="IDV")
    owner = v1.owner_of(user.pubkey())
    tp_slot, ap_slot = tp.allocate_slot(owner), ap.allocate_slot(owner)
    policy = IdentityEvidencePolicy({"idv": v1.pk_hex(idv.pubkey())})
    ctx = build_context(tp_hsm=tp, db_path=str(tmp_path / "identity.json"),
                        clock=clock, identity_policy=policy)
    intake = IdentityIntake(ctx)
    no_evidence = _cr(user=user, tp=tp, ap=ap, tp_slot=tp_slot, ap_slot=ap_slot)
    with pytest.raises(v1.ProtocolError, match="身份核验证据"):
        intake.submit(cr_box=no_evidence, caller=owner)

    evidence = v1.identity_evidence.issue(
        verifier_hsm=idv, issuer="idv", hid=v1.hid_of("synthetic-person-001"),
        user_sign_pk=v1.pk_hex(user.pubkey()), tp_nonce=tp_slot[0],
        request_id="cr-evidence-001", method="in-person-reviewed",
        assurance_level="substantial", evidence_ref="synthetic-case",
        issued_at=clock.now(), expires_at="2026-11-07T12:00:00")
    cr = _cr(user=user, tp=tp, ap=ap, tp_slot=tp_slot, ap_slot=ap_slot, evidence=evidence)
    accepted = intake.submit(cr_box=cr, caller=owner)
    assert intake.opened_for_issue(accepted["applicationId"])[0].identity_evidence == evidence
    clock.at = "2026-11-07T12:00:00"
    with pytest.raises(v1.ProtocolError, match="过期"):
        intake.opened_for_issue(accepted["applicationId"])


def test_test_adapter_explicitly_allows_synthetic_identity(tmp_path):
    user = v1.make_demo_hsm(domain="USER")
    tp = v1.make_demo_hsm(domain="TP")
    ap = v1.make_demo_hsm(domain="AP")
    owner = v1.owner_of(user.pubkey())
    cr = _cr(user=user, tp=tp, ap=ap,
             tp_slot=tp.allocate_slot(owner), ap_slot=ap.allocate_slot(owner))
    ctx = build_context(tp_hsm=tp, db_path=str(tmp_path / "identity.json"),
                        clock=FixedClock("2026-11-06T12:00:00"), test_adapter=True)
    assert IdentityIntake(ctx).submit(cr_box=cr, caller=owner)["state"] == "pending_review"
