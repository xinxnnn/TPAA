"""TPAA v1 authenticated HTTP integration contracts."""
from __future__ import annotations

import importlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import pytest
    from fastapi.testclient import TestClient
except ImportError:
    pytest = None
    TestClient = None

from tests.tpaa_v1_flow import *  # noqa: F403
import crypto.sdk

v1 = crypto.sdk.v1
NOW = "2026-10-14T10:00:00"
EXP = "2026-10-14T11:00:00"
PII = {"ID": "110101199003071234", "name": "张三"}
BI = {"iris": "iris-template-demo"}
SEL = [{"moduleId": "summarize", "version": "1.0.0"},
       {"moduleId": "translate", "version": "1.0.0"}]


def _skip() -> None:
    if TestClient is None:
        from run_tests import Skipped
        raise Skipped("需要 fastapi + httpx")


def _svc(side: str, name: str, mod: str = "app"):
    module_side = {"user-side": "user_side", "tp-side": "tp_side", "ap-side": "ap_side",
                   "cross-domain": "cross_domain", "ipfs": "ipfs"}[side]
    module_name = "storage_service" if module_side == "ipfs" else name.replace("-", "_")
    return importlib.import_module(f"services.{module_side}.{module_name}.{mod}")


def _bearer(tok: str) -> dict:
    return {"Authorization": "Bearer " + tok}


class Rig:
    def __init__(self) -> None:
        from services.ipfs.storage_service.app import StorageService
        from services.shared.v1_auth import AuthIssuer
        from services.shared.v1_http import FixedClock
        from localstore import Layout, ModuleRepo
        from user_credential_handler import UserCredentialHandler

        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.clock = FixedClock(NOW)
        self.storage = StorageService()
        self.sup = sup_key()  # noqa: F405
        tp_hsm, ap_hsm = v1.make_demo_hsm(domain="TP"), v1.make_demo_hsm(domain="AP")
        self.tp_hsm, self.ap_hsm = tp_hsm, ap_hsm
        rv_hsm = v1.make_demo_hsm(domain="REVIEW")
        roles = {"reviewer-a": "reviewer", "operator": "tp-operator",
                 "sup-a": "supervisor", "sup-b": "supervisor", "sup-rogue": "supervisor"}
        self.staff = {name: v1.make_demo_hsm(domain="STAFF") for name in roles}
        directory = {v1.pk_hex(h.pubkey()): {"id": name, "role": roles[name],
                                             "encPub": format(h.enc_pub(), "x")}
                     for name, h in self.staff.items()}
        self.tp_auth = AuthIssuer(issuer_hsm=v1.make_demo_hsm(domain="AUTH"), aud="tpaa:tp",
                                  clock=self.clock, staff=directory)
        self.ap_auth = AuthIssuer(issuer_hsm=v1.make_demo_hsm(domain="AUTH"), aud="tpaa:ap",
                                  clock=self.clock)

        self.modules = ModuleRepo(Layout(d / "ap-store"))
        self.modules.publish("summarize", "1.0.0", {"engine.py": b"def run(t):\n    return t[:80]\n"})
        self.modules.publish("translate", "1.0.0", {"engine.py": b"def run(t, l):\n    return t\n"})
        agent = _svc("ap-side", "agent-service", "v1_app")
        self.agent_ctx = agent.build_context(ap_hsm=ap_hsm, modules=self.modules,
                                             tp_sign_pk=tp_hsm.pubkey(), sup_pub=self.sup.public(),
                                             domain2="ap.example", db_path=str(d / "agent.json"),
                                             clock=self.clock,
                                             supervisors={v1.pk_hex(self.staff[n].pubkey())
                                                          for n in ("sup-a", "sup-b")},
                                             tp_enc_pk=tp_hsm.enc_pub(),
                                             runtime_tp_hsm=tp_hsm)
        self.ap = TestClient(agent.create_app(ctx=self.agent_ctx, auth=self.ap_auth))
        self.ap_keys = self.ap.get("/v1/tpaa/keys").json()

        ident = _svc("tp-side", "identity-service")
        iw = _svc("tp-side", "identity-service", "infra.wiring")
        ictx = iw.build_context(tp_hsm=tp_hsm, db_path=str(d / "identity.json"),
                                 clock=self.clock, test_adapter=True)
        self.ident = TestClient(ident.create_app(ctx=ictx, auth=self.tp_auth))
        rev = _svc("tp-side", "review-service")
        rctx = rev.build_context(review_hsm=rv_hsm, identity=self.ident.app.state.intake,
                                 db_path=str(d / "review.json"), clock=self.clock)
        self.ident.app.state.ctx.review = rev.ReviewDesk(rctx)
        self.rev = TestClient(rev.create_app(ctx=rctx, verifier=self.tp_auth.verifier()))
        phc = _svc("tp-side", "phc-service")
        pctx = phc.build_context(tp_hsm=tp_hsm, identity=self.ident.app.state.intake,
                                 review=self.ident.app.state.ctx.review,
                                 review_pk=rv_hsm.pubkey(), ap_bundle=self.ap_keys,
                                 sup_pub=self.sup.public(), storage=self.storage,
                                 domain1="tp.example", db_path=str(d / "phc.json"), clock=self.clock,
                                 allow_demo_scid_reveal=True)
        self.phc = TestClient(phc.create_app(ctx=pctx, verifier=self.tp_auth.verifier()))
        self.wallet = UserCredentialHandler(d / "wallet")
        self.tokens = {}

    def login(self, client, signer):
        ch = client.post("/v1/auth/challenge").json()
        response = client.post("/v1/auth/login", json=signer(ch))
        assert response.status_code == 200, response.text
        return response.json()["token"]

    def user(self, wallet=None, side="tp"):
        wallet = wallet or self.wallet
        key = (wallet.owner, side)
        if key not in self.tokens:
            self.tokens[key] = self.login(self.ident if side == "tp" else self.ap, wallet.login_body)
        return _bearer(self.tokens[key])

    def staff_hdr(self, name):
        if name not in self.tokens:
            staff = self.staff[name]
            self.tokens[name] = self.login(self.ident, lambda ch: {
                "challenge": ch["challenge"], "signPk": v1.pk_hex(staff.pubkey()),
                "sig": v1.auth.sign_login(staff, challenge=ch["challenge"], aud=ch["aud"])})
        return _bearer(self.tokens[name])

    def apply(self, label, wallet=None):
        wallet = wallet or self.wallet
        tp_slot = self.ident.post("/v1/slots", json={"userSignPk": wallet.sign_pk_hex},
                                  headers=self.user(wallet)).json()
        ap_slot = self.ap.post("/v1/tpaa/slots", json={"userSignPk": wallet.sign_pk_hex},
                               headers=self.user(wallet, "ap")).json()
        cr = wallet.build_cr(label=label, pii=PII, bi=BI,
                             tp_keys=self.ident.get("/v1/keys").json(), ap_keys=self.ap_keys,
                             tp_slot=tp_slot, ap_slot=ap_slot, expires=EXP)
        response = self.ident.post("/v1/applications", json={"cr": cr}, headers=self.user(wallet))
        assert response.status_code == 200, response.text
        app_id = response.json()["applicationId"]
        wallet.set_application(label, app_id)
        return app_id, cr

    def close(self):
        self.tmp.cleanup()


def test_tp_opens_signed_cr_after_legacy_slot_binding_was_lost():
    rig = Rig()
    try:
        _, cr = rig.apply("legacy-slot-recovery")
        previous_hsm = rig.tp_hsm
        restarted_hsm = v1.make_demo_hsm(
            domain="TP", root=previous_hsm._root, schnorr_sk=previous_hsm._schnorr_sk,
            chameleon_sk=previous_hsm._chameleon.sk)

        opened = v1.tp.tp_open_cr(tp_hsm=restarted_hsm, cr_box=cr, now=NOW,
                                  recover_missing_slot=True)

        assert opened.owner == rig.wallet.owner
        assert restarted_hsm.slot_public(opened.tp_nonce) == opened.af.t_pub
    finally:
        rig.close()


def _happy() -> dict:
    r = Rig()
    app_id, cr = r.apply("happy")
    decision = r.rev.post(f"/v1/reviews/{app_id}", json={"decision": "approve"},
                          headers=r.staff_hdr("reviewer-a"))
    assert decision.status_code == 200, decision.text
    issued = r.phc.post(f"/v1/phc/{app_id}/issue", headers=r.user())
    assert issued.status_code == 200, issued.text
    r.wallet.accept_rr("happy", issued.json()["rr"])
    ar = r.wallet.build_ar("happy", expires=EXP)
    session = r.ap.post("/v1/tpaa/sessions", json={"ar": ar, "applicationId": app_id},
                        headers=r.user(side="ap"))
    assert session.status_code == 200, session.text
    r.wallet.open_cmm("happy", session.json()["cmm"])
    paci = r.wallet.build_paci("happy", selection=SEL)
    build = r.ap.post(f"/v1/tpaa/sessions/{session.json()['sessionId']}/build",
                      json={"paci": paci}, headers=r.user(side="ap"))
    assert build.status_code == 200, build.text
    r.wallet.accept_par("happy", build.json()["par"])
    return {"rig": r, "app": app_id, "cr": cr, "ar": ar, "paci": paci,
            "build": build.json(), "session": session.json()}


def test_v1_malicious_trace_requires_ap_approved_dual_signatures_and_seals_identity():
    flow = _happy()
    r = flow["rig"]
    try:
        didgr = r.wallet.build_didgr("happy", expires=EXP)
        finalized = r.phc.post(
            f"/v1/phc/{flow['app']}/finalize", json={"didgr": didgr}, headers=r.user())
        assert finalized.status_code == 200, finalized.text
        r.wallet.verify_final("happy", finalized.json()["final"], finalized.json()["attestation"])
        r.wallet.accept_final("happy")
        did = r.phc.app.state.desk.status(app_id=flow["app"])["did"]

        supervision = _svc("tp-side", "supervision-service", "v1_app")
        ap_supervisors = {v1.pk_hex(r.staff[name].pubkey()) for name in ("sup-a", "sup-b")}
        assert ap_supervisors == r.agent_ctx.supervisors
        legacy_ctx = supervision.build_context(
            tp_hsm=r.tp_hsm, sup_key=r.sup, records=r.phc.app.state.desk,
            storage=r.storage,
            ap_assist=lambda request: r.ap.app.state.desk.assist(request)["answer"],
            staff=r.tp_auth.staff, db_path=str(Path(r.tmp.name) / "legacy-supervision.json"),
            clock=r.clock, legacy_dids={did})
        legacy_client = TestClient(
            supervision.create_app(ctx=legacy_ctx, verifier=r.tp_auth.verifier()))
        legacy_targets = legacy_client.get("/v1/targets", headers=r.staff_hdr("reviewer-a"))
        assert legacy_targets.status_code == 200
        assert legacy_targets.json() == {"items": [], "excludedLegacyCount": 1}
        legacy_report = legacy_client.post("/v1/cases", json={
            "did": did, "purpose": "legacy test", "allegation": "legacy synthetic case",
        }, headers=r.staff_hdr("reviewer-a"))
        assert legacy_report.status_code == 409, legacy_report.text
        legacy_client.close()

        ctx = supervision.build_context(
            tp_hsm=r.tp_hsm, sup_key=r.sup, records=r.phc.app.state.desk,
            storage=r.storage,
            ap_assist=lambda request: r.ap.app.state.desk.assist(request)["answer"],
            staff=r.tp_auth.staff, db_path=str(Path(r.tmp.name) / "supervision.json"),
            clock=r.clock,
            forensic_open=lambda staff_id, box: v1.case.open_forensic(r.staff[staff_id], box))
        client = TestClient(supervision.create_app(ctx=ctx, verifier=r.tp_auth.verifier()))
        purpose = "调查该智能体涉嫌冒用身份的投诉"
        reported = client.post("/v1/cases", json={
            "did": did, "purpose": purpose, "allegation": "合成恶意行为追溯测试",
            "evidenceRef": "synthetic-evidence-1",
        }, headers=r.staff_hdr("reviewer-a"))
        assert reported.status_code == 200, reported.text
        case_id = reported.json()["caseId"]

        headers_a, headers_b = r.staff_hdr("sup-a"), r.staff_hdr("sup-b")
        signature_a = v1.case.sign_case_approval(
            r.staff["sup-a"], case_id=case_id, did=did, purpose=purpose)
        signature_b = v1.case.sign_case_approval(
            r.staff["sup-b"], case_id=case_id, did=did, purpose=purpose)
        first = client.post(f"/v1/cases/{case_id}/approve",
                            json={"approval": signature_a}, headers=headers_a)
        assert first.status_code == 200 and first.json()["approvalCount"] == 1
        premature = client.post(f"/v1/cases/{case_id}/disclose", headers=headers_a)
        assert premature.status_code == 403, premature.text
        second = client.post(f"/v1/cases/{case_id}/approve",
                             json={"approval": signature_b}, headers=headers_b)
        assert second.status_code == 200 and second.json()["state"] == "filed"
        premature_identity = client.get(
            f"/v1/cases/{case_id}/identity", headers=headers_a)
        assert premature_identity.status_code == 409, premature_identity.text

        result = client.post(f"/v1/cases/{case_id}/disclose", headers=headers_a)
        assert result.status_code == 200, result.text
        assert result.json()["state"] == "sealed"
        assert PII["ID"] not in result.text and PII["name"] not in result.text
        assert BI["iris"] not in result.text
        opened_forensic = v1.case.open_forensic(r.staff["sup-a"], result.json()["forensic"])
        assert opened_forensic["did"] == did
        assert opened_forensic["PII"] == PII
        assert opened_forensic["BI"] == BI

        case_list = client.get("/v1/cases", headers=headers_a)
        assert case_list.status_code == 200, case_list.text
        assert case_list.json()["items"][0]["state"] == "sealed"
        assert PII["ID"] not in case_list.text and PII["name"] not in case_list.text
        persisted = client.get(f"/v1/cases/{case_id}/forensic", headers=headers_a)
        assert persisted.status_code == 200, persisted.text
        denied = client.get(f"/v1/cases/{case_id}/forensic", headers=headers_b)
        assert denied.status_code == 403, denied.text

        identity = client.get(f"/v1/cases/{case_id}/identity", headers=headers_a)
        assert identity.status_code == 200, identity.text
        assert identity.headers["cache-control"] == "no-store"
        assert identity.json()["pii"] == PII
        assert identity.json()["biFields"] == ["iris"]
        assert BI["iris"] not in identity.text
        assert identity.json()["identityVerified"] is True
        denied_identity = client.get(
            f"/v1/cases/{case_id}/identity", headers=headers_b)
        assert denied_identity.status_code == 403, denied_identity.text
        stored_case = ctx.store.load()["cases"][case_id]
        assert stored_case["identityAccesses"][-1]["by"] == "sup-a"
        assert "PII" not in stored_case["identityAccesses"][-1]
    finally:
        r.close()


def test_d4_retry_replays_saved_result_and_rejects_changed_paci():
    flow = _happy()
    r = flow["rig"]
    try:
        sid = flow["session"]["sessionId"]
        path = f"/v1/tpaa/sessions/{sid}/build"
        replay = r.ap.post(path, json={"paci": flow["paci"]}, headers=r.user(side="ap"))
        assert replay.status_code == 200, replay.text
        assert replay.json() == flow["build"]

        changed_paci = {**flow["paci"], "ct": flow["paci"]["ct"] + "00"}
        conflict = r.ap.post(path, json={"paci": changed_paci}, headers=r.user(side="ap"))
        assert conflict.status_code == 409, conflict.text
        assert "不同 PACI" in conflict.json()["message"]
    finally:
        r.close()


def test_legacy_d4_timeout_can_recover_only_the_original_configuration():
    flow = _happy()
    r = flow["rig"]
    try:
        sid = flow["session"]["sessionId"]

        def remove_new_version_cache(state):
            session = state["sessions"][sid]
            session.pop("buildRequestDigest", None)
            session.pop("buildResult", None)
            return state

        r.agent_ctx.store.update(remove_new_version_cache)
        path = f"/v1/tpaa/sessions/{sid}/build"
        recovered = r.ap.post(path, json={"paci": flow["paci"]}, headers=r.user(side="ap"))
        assert recovered.status_code == 200, recovered.text
        assert recovered.json()["recordId"] != flow["build"]["recordId"]
        assert recovered.json()["event"]["artifacts"]["cmi"] == \
            flow["build"]["event"]["artifacts"]["cmi"]
        assert recovered.json()["event"]["artifacts"]["recoveredFromRecordId"] == \
            flow["build"]["recordId"]
        assert flow["build"]["recordId"] in r.agent_ctx.store.load()["records"]

        replay = r.ap.post(path, json={"paci": flow["paci"]}, headers=r.user(side="ap"))
        assert replay.status_code == 200, replay.text
        assert replay.json() == recovered.json()

        changed_paci = {**flow["paci"], "ct": flow["paci"]["ct"] + "00"}
        conflict = r.ap.post(path, json={"paci": changed_paci}, headers=r.user(side="ap"))
        assert conflict.status_code == 409, conflict.text
    finally:
        r.close()


def test_reviewer_queue_is_masked_and_authorized(monkeypatch) -> None:
    _skip()
    r = _happy()["rig"]
    app_id, _ = r.apply("queue")
    denied = r.ident.post("/v1/applications/review-queue", json={}, headers=r.user(r.wallet))
    assert denied.status_code == 403, denied.text
    intake = r.ident.app.state.intake
    assert intake._get(app_id)["reviewMetadata"] == {
        "pii": {"ID": "110************234", "name": "**"},
        "biFields": ["iris"],
    }
    monkeypatch.setattr(
        intake, "_reopen",
        lambda _: pytest.fail("review queue must not decrypt every application"))
    response = r.ident.post("/v1/applications/review-queue", json={}, headers=r.staff_hdr("reviewer-a"))
    assert response.status_code == 200, response.text
    item = next(x for x in response.json()["items"] if x["applicationId"] == app_id)
    assert item["state"] == "pending_review"
    assert PII["ID"] not in str(item) and PII["name"] not in str(item) and BI["iris"] not in str(item)
    assert item["biFields"] == ["iris"] and item["crDigest"]


def test_reviewer_queue_tracks_decisions_without_returning_notes() -> None:
    _skip()
    r = _happy()["rig"]
    app_id, _ = r.apply("queue-decide")
    decision = r.rev.post(f"/v1/reviews/{app_id}", json={"decision": "approve", "note": "internal note"},
                          headers=r.staff_hdr("reviewer-a"))
    assert decision.status_code == 200, decision.text
    response = r.ident.post("/v1/applications/review-queue", json={}, headers=r.staff_hdr("reviewer-a"))
    item = next(x for x in response.json()["items"] if x["applicationId"] == app_id)
    assert item["state"] == "approved" and item["review"]["approved"]
    assert "internal note" not in response.text
