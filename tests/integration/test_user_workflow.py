from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.integration.test_tpaa_v1_http import Rig, NOW, PII, BI, SEL
from user_credential_handler import UserCredentialHandler
import crypto.sdk
from services.user_side.portal_api.app import create_app
from services.user_side.portal_api.infra.integration_rig import IntegrationRig


def test_portal_api_runs_g1_through_g4_with_real_tp_single_review():
    tp_rig = Rig()
    user_hsm = tp_rig.wallet.hsm
    adapter = IntegrationRig(
        tp_rig.tmp.name, tp_rig.clock, user_hsm,
        tp_rig.ap.app, tp_rig.ap.app, tp_rig.phc.app,
        tp_rig.ident.app, tp_rig.rev.app, tp_rig.tp_auth, tp_rig.ap_auth)
    portal_ctx = adapter.portal_context(Path(tp_rig.tmp.name) / "portal.json",
                                        Path(tp_rig.tmp.name) / "portal-wallets")
    portal = TestClient(create_app(ctx=portal_ctx))
    user_token = portal_ctx.auth.token_for(adapter.portal_handlers[tp_rig.wallet.owner].sign_pk_hex)["token"]
    headers = {"Authorization": f"Bearer {user_token}"}

    initialization = portal.get("/api/user/v1/initialize", headers=headers)
    assert initialization.status_code == 200, initialization.text
    init_body = initialization.json()
    assert init_body["publicParameters"]["dl"]["pBits"] == 3072
    assert init_body["publicParameters"]["ellipticCurve"]["name"] == "secp256k1"
    assert init_body["checks"]["dlGeneratorInSubgroup"] is True
    assert init_body["checks"]["paillierGeneratorMatchesModulus"] is True
    assert init_body["publicKeys"]["user"]["pk"] == init_body["userSignPk"]

    test_photo = b"\x89PNG\r\n\x1a\nsynthetic-test-image"
    bi_with_photo = {**BI, "facePhoto": "data:image/png;base64," +
                     base64.b64encode(test_photo).decode("ascii")}
    submitted = portal.post("/api/user/v1/applications",
                            json={"pii": PII, "bi": bi_with_photo}, headers=headers)
    assert submitted.status_code == 200, submitted.text
    assert base64.b64encode(test_photo).decode("ascii") not in submitted.text
    application_id = submitted.json()["applicationId"]
    decrypted_demo = portal.get(
        f"/api/user/v1/applications/{application_id}/decrypted-demo", headers=headers)
    assert decrypted_demo.status_code == 200, decrypted_demo.text
    demo_result = decrypted_demo.json()
    assert demo_result["signatureVerified"] is True
    assert demo_result["biFields"] == sorted(bi_with_photo)
    assert demo_result["facePhoto"]["present"] is True
    assert demo_result["facePhoto"]["mediaType"] == "image/png"
    assert demo_result["facePhoto"]["encodedBytes"] > 0
    assert demo_result["hashCalculations"]["H(ID)"]["result"].startswith("computed")
    assert demo_result["hashCalculations"]["crDigest"]["result"]
    assert demo_result["hashCalculations"]["AF"]["resultHex"]
    assert all(value not in decrypted_demo.text for value in (*PII.values(), *BI.values()))
    assert base64.b64encode(test_photo).decode("ascii") not in decrypted_demo.text
    g1 = next(event for event in submitted.json()["events"] if event["stage"] == "G1")
    assert g1["artifacts"]["applicationId"] == application_id
    assert g1["artifacts"]["encryptedCRAccepted"] is True
    assert g1["artifacts"]["recipient"] == "TP identity-service"
    assert g1["artifacts"]["submittedPIIFields"] == sorted(PII)
    assert g1["artifacts"]["submittedBIFields"] == sorted(bi_with_photo)
    assert all(value not in submitted.text for value in (*PII.values(), *BI.values()))

    def staff_signin(challenge):
        staff = tp_rig.staff["reviewer-a"]
        return {"challenge": challenge["challenge"],
                "signPk": crypto.sdk.v1.pk_hex(staff.pubkey()),
                "sig": crypto.sdk.v1.auth.sign_login(staff, challenge=challenge["challenge"], aud=challenge["aud"])}
    staff_token = tp_rig.login(tp_rig.ident, staff_signin)
    staff_headers = {"Authorization": f"Bearer {staff_token}"}
    tp_queue = tp_rig.ident.post(
        "/v1/applications/review-queue", headers=staff_headers)
    assert tp_queue.status_code == 200, tp_queue.text
    assert any(item["applicationId"] == application_id
               for item in tp_queue.json()["items"])
    # Use existing authenticated TP reviewer credential to approve through review-service.
    reviewer_view = tp_rig.ident.get(
        f"/v1/applications/{application_id}/review",
        headers={"Authorization": f"Bearer {staff_token}"})
    assert reviewer_view.status_code == 200, reviewer_view.text
    assert "facePhoto" in reviewer_view.json()["biFields"]
    assert base64.b64encode(test_photo).decode("ascii") not in reviewer_view.text
    review = tp_rig.rev.post(f"/v1/reviews/{application_id}", json={"decision": "approve"},
                             headers=staff_headers)
    assert review.status_code == 200, review.text
    assert portal.get(f"/api/user/v1/applications/{application_id}/timeline", headers=headers).json()["nextAction"] == "issue"

    issued = portal.post(f"/api/user/v1/applications/{application_id}/issue", headers=headers)
    assert issued.status_code == 200, issued.text
    g3 = next(event for event in issued.json()["events"] if event["stage"] == "G3")
    assert g3["artifacts"]["applicationId"] == application_id
    assert g3["artifacts"]["sourceCRDigest"] == g1["artifacts"]["crDigest"]
    assert g3["artifacts"]["identityBindingVerifiedByTP"] is True
    tp_record = crypto.sdk.v1.records.load(
        tp_rig.phc.app.state.ctx.store.load()["records"][application_id])
    assert tp_record.hid == crypto.sdk.v1.hid_of(PII["ID"])
    assert tp_record.hid != crypto.sdk.v1.hid_of("different-user-id")
    assert g3["artifacts"]["phcDigest"] == tp_record.phc_digest
    assert "phc" not in g3["artifacts"]
    g4 = portal.post(f"/api/user/v1/applications/{application_id}/accept-g4", headers=headers)
    assert g4.status_code == 200, g4.text
    timeline = g4.json()
    assert [e["stage"] for e in timeline["events"]] == ["INIT", "G1", "REVIEW", "G3", "G4"]
    assert timeline["events"][-1]["artifacts"]["phcDigest"] == g3["artifacts"]["phcDigest"]
    assert "phc" not in timeline["events"][-1]["artifacts"]
    assert timeline["nextAction"] == "start-agent"


def test_portal_api_runs_d1_through_final_phc_from_real_cmm():
    tp_rig = Rig()
    adapter = IntegrationRig(
        tp_rig.tmp.name, tp_rig.clock, tp_rig.wallet.hsm,
        tp_rig.ap.app, tp_rig.ap.app, tp_rig.phc.app,
        tp_rig.ident.app, tp_rig.rev.app, tp_rig.tp_auth, tp_rig.ap_auth)
    portal_ctx = adapter.portal_context(Path(tp_rig.tmp.name) / "portal.json",
                                        Path(tp_rig.tmp.name) / "portal-wallets")
    portal = TestClient(create_app(ctx=portal_ctx))
    owner = tp_rig.wallet.owner
    token = portal_ctx.auth.token_for(adapter.portal_handlers[owner].sign_pk_hex)["token"]
    headers = {"Authorization": f"Bearer {token}"}

    created = portal.post("/api/user/v1/applications", json={"pii": PII, "bi": BI}, headers=headers)
    assert created.status_code == 200, created.text
    app_id = created.json()["applicationId"]
    staff = tp_rig.staff["reviewer-a"]
    signin = lambda challenge: {"challenge": challenge["challenge"],
                                "signPk": crypto.sdk.v1.pk_hex(staff.pubkey()),
                                "sig": crypto.sdk.v1.auth.sign_login(staff, challenge=challenge["challenge"],
                                                                      aud=challenge["aud"])}
    staff_token = tp_rig.login(tp_rig.ident, signin)
    review = tp_rig.rev.post(f"/v1/reviews/{app_id}", json={"decision": "approve"},
                             headers={"Authorization": f"Bearer {staff_token}"})
    assert review.status_code == 200, review.text

    for action in ("issue", "accept-g4"):
        response = portal.post(f"/api/user/v1/applications/{app_id}/{action}", headers=headers)
        assert response.status_code == 200, response.text

    d1 = portal.post(f"/api/user/v1/applications/{app_id}/begin-agent", headers=headers)
    assert d1.status_code == 200, d1.text
    d1_event = next(event for event in d1.json()["events"] if event["stage"] == "D1")
    assert d1_event["artifacts"]["requestId"]
    assert d1_event["artifacts"]["cmmVersion"]
    assert "arEnvelope" not in d1_event["artifacts"]
    restored_timeline = portal.get(
        f"/api/user/v1/applications/{app_id}/timeline", headers=headers)
    assert restored_timeline.status_code == 200, restored_timeline.text
    restored_d1 = next(event for event in restored_timeline.json()["events"]
                       if event["stage"] == "D1")
    assert restored_d1 == d1_event
    d2_event = next(event for event in d1.json()["events"] if event["stage"] == "D2")
    assert d2_event["artifacts"]["cmm"]["categories"]
    catalog = d1.json()["catalog"]
    selection = [{"moduleId": category["id"], "version": category["options"][0]}
                 for category in catalog if category["options"]]
    assert selection, catalog
    post_agent = portal_ctx.agent.post_fn
    lost_first_response = True

    def lose_first_build_response(path, body, request_owner):
        nonlocal lost_first_response
        result = post_agent(path, body, request_owner)
        if "/build" in path and lost_first_response:
            lost_first_response = False
            raise RuntimeError("simulated AP response timeout after successful D4")
        return result

    portal_ctx.agent.post_fn = lose_first_build_response
    with pytest.raises(RuntimeError, match="simulated AP response timeout"):
        portal.post(f"/api/user/v1/applications/{app_id}/build-agent",
                    json={"selection": selection}, headers=headers)
    assert portal.get(f"/api/user/v1/applications/{app_id}/timeline",
                      headers=headers).json()["state"] == "cmm_received"

    d4 = portal.post(f"/api/user/v1/applications/{app_id}/build-agent",
                     json={"selection": selection}, headers=headers)
    assert d4.status_code == 200, d4.text
    assert {event["stage"] for event in d4.json()["events"]} >= {"D1", "D2", "D3", "D4"}
    d4_event = next(event for event in d4.json()["events"] if event["stage"] == "D4")
    assert d4_event["artifacts"]["moduleCount"] == len(selection)
    assert d4_event["artifacts"]["modules"]
    assert all(len(module["digest"]) == 64 for module in d4_event["artifacts"]["modules"])
    assert d4_event["artifacts"]["cmiAlgorithm"].startswith("CMI=HCGen")
    assert d4_event["artifacts"]["parDigest"]
    hash_trace = d4_event["artifacts"]["hashCalculations"]
    assert hash_trace["hashFunction"] == "SHA-256"
    assert hash_trace["result"] == d4_event["artifacts"]["cmi"]
    assert len(hash_trace["steps"]) == len(selection)
    assert hash_trace["steps"][0]["digest"] == d4_event["artifacts"]["modules"][0]["digest"]
    assert hash_trace["parDigest"] == d4_event["artifacts"]["parDigest"]
    assert "par" not in d4_event["artifacts"]
    d3_event = next(event for event in d4.json()["events"] if event["stage"] == "D3")
    assert d3_event["artifacts"]["selection"] == selection
    assert d3_event["artifacts"]["selectionDigest"]
    assert hash_trace["selectionDigest"] == d3_event["artifacts"]["selectionDigest"]
    assert "paciEnvelope" not in d3_event["artifacts"]

    d5 = portal.post(f"/api/user/v1/applications/{app_id}/accept-d5", headers=headers)
    assert d5.status_code == 200, d5.text
    d5_event = next(event for event in d5.json()["events"] if event["stage"] == "D5")
    assert d5_event["artifacts"]["cmi"] == d4_event["artifacts"]["cmi"]
    assert d5_event["artifacts"]["statementDigest"]
    assert d5_event["artifacts"]["phc"]["ASO"]["APM"]["CMI"] == d5_event["artifacts"]["cmi"]
    d5_hash_trace = d5_event["artifacts"]["hashCalculations"]
    assert d5_hash_trace["phcDigest"] == d5_event["artifacts"]["phcDigest"]
    assert d5_hash_trace["modulesDigest"] == d5_event["artifacts"]["d4Statement"]["modulesDigest"]
    assert d5_hash_trace["afRef"] == d5_event["artifacts"]["d4Statement"]["afRef"]
    assert d5_event["artifacts"]["cmiRecomputed"] is True
    confirm = portal.post(f"/api/user/v1/applications/{app_id}/confirm-d5", headers=headers)
    assert confirm.status_code == 200, confirm.text
    d6 = portal.post(f"/api/user/v1/applications/{app_id}/finalize-d6", headers=headers)
    assert d6.status_code == 200, d6.text
    assert d6.json()["nextAction"] == "verify-final"
    assert d6.json()["events"][-1]["stage"] == "D6"
    premature_accept = portal.post(
        f"/api/user/v1/applications/{app_id}/accept-final", headers=headers)
    assert premature_accept.status_code == 400

    final_verified = portal.post(f"/api/user/v1/applications/{app_id}/verify-final", headers=headers)
    assert final_verified.status_code == 200, final_verified.text
    assert final_verified.json()["nextAction"] == "accept-final"
    assert final_verified.json()["events"][-1]["status"] == "verified_by_user_executor"
    d6_event = next(event for event in final_verified.json()["events"] if event["stage"] == "D6")
    final_event = final_verified.json()["events"][-1]
    assert d6_event["artifacts"]["phcDigest"] == final_event["artifacts"]["phcDigest"]
    assert final_event["artifacts"]["did"]
    assert all("phc" not in event["artifacts"] for event in (d6_event, final_event))

    final_accepted = portal.post(f"/api/user/v1/applications/{app_id}/accept-final", headers=headers)
    assert final_accepted.status_code == 200, final_accepted.text
    assert final_accepted.json()["nextAction"] is None
    assert final_accepted.json()["events"][-1]["status"] == "user_accepted"
    scid_demo = portal.get(
        f"/api/user/v1/applications/{app_id}/scid-demo", headers=headers)
    assert scid_demo.status_code == 200, scid_demo.text
    scid_result = scid_demo.json()
    did = next(event["artifacts"]["did"] for event in final_accepted.json()["events"]
               if event["stage"] == "FINAL" and event["status"] == "user_accepted")
    scid_value = did.split(":")[2]
    scid_box = json.loads(base64.urlsafe_b64decode(
        scid_value + "=" * (-len(scid_value) % 4)))
    assert scid_result["encoding"] == "Base64URL(CSCID ciphertext)"
    expected_scid_plaintext = tp_rig.tp_hsm.pke_open(scid_box, tag="CSCID")
    assert scid_result["plaintext"] == expected_scid_plaintext
    assert scid_result["plaintext"].keys() == {"AF", "RF"}
    assert scid_result["did"] == did

    expected_stages = {"INIT", "G1", "REVIEW", "G3", "G4", "D1", "D2", "D3", "D4",
                       "D5", "D6", "FINAL"}
    assert {event["stage"] for event in final_accepted.json()["events"]} == expected_stages
    assert final_accepted.json()["state"] == "d6_accepted"
    assert portal.post(f"/api/user/v1/applications/{app_id}/publish",
                       headers=headers).status_code == 404
    assert portal.post(f"/api/user/v1/applications/{app_id}/start-runtime",
                       headers=headers).status_code == 404
    for response in (created, d1, d4, d5, confirm, d6, final_verified, final_accepted):
        for secret_value in (*PII.values(), *BI.values()):
            assert secret_value not in response.text


def test_portal_rejects_cross_owner_timeline():
    tp_rig = Rig()
    adapter = IntegrationRig(tp_rig.tmp.name, tp_rig.clock, tp_rig.wallet.hsm,
                             tp_rig.ap.app, tp_rig.ap.app, tp_rig.phc.app,
                             tp_rig.ident.app, tp_rig.rev.app, tp_rig.tp_auth, tp_rig.ap_auth)
    portal_ctx = adapter.portal_context(Path(tp_rig.tmp.name) / "portal.json",
                                        Path(tp_rig.tmp.name) / "portal-wallets")
    client = TestClient(create_app(ctx=portal_ctx))
    wallet = UserCredentialHandler(Path(tp_rig.tmp.name) / "other-wallet")
    other_owner = wallet.owner
    row = {"applicationId": "app-owned", "owner": tp_rig.wallet.owner, "walletLabel": "none",
           "state": "pending_review", "events": []}
    portal_ctx.store.save({"applications": {"app-owned": row}})
    token = portal_ctx.auth.token_for(wallet.sign_pk_hex)["token"]
    response = client.get("/api/user/v1/applications/app-owned/timeline",
                          headers={"Authorization": f"Bearer {token}"})
    decrypted_response = client.get(
        "/api/user/v1/applications/app-owned/decrypted-demo",
        headers={"Authorization": "Bearer " + token})
    assert other_owner != tp_rig.wallet.owner
    assert response.status_code == 403
    assert decrypted_response.status_code == 403, decrypted_response.text
