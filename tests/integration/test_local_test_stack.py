"""Contract tests for the local service port matrix."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from scripts.prepare_local_test import main as prepare_main
from services.tp_side.identity_service.domain.usecases.intake import IdentityIntake


def test_reviewer_detail_includes_safe_review_decision():
    ctx = SimpleNamespace(
        demo_photo_preview=False,
        progress_review=lambda _: {
            "applicationId": "app-safe",
            "state": "approved",
            "approved": True,
            "decisions": [{"reviewer": "reviewer-a", "decision": "approve", "at": "now",
                           "note": "must not leave service"}],
        })
    intake = IdentityIntake(ctx)
    intake._get = lambda _: {"applicationId": "app-safe", "crDigest": "digest",
                             "receivedAt": "now", "state": "pending_review"}
    photo = "data:image/png;base64,c3ludGhldGlj"
    intake._reopen = lambda _: SimpleNamespace(
        pii={"name": "Sensitive Name"}, bi={"iris": "Sensitive BI", "facePhoto": photo})

    result = intake.review_view("app-safe")

    assert result["state"] == "approved"
    assert result["review"]["approved"] is True
    assert result["review"]["decisions"] == [
        {"reviewer": "reviewer-a", "decision": "approve", "at": "now"}]
    assert result["pii"]["name"] != "Sensitive Name"
    assert "Sensitive BI" not in repr(result)
    assert "demoFacePhotoPreview" not in result

    ctx.demo_photo_preview = True
    assert intake.review_view("app-safe")["demoFacePhotoPreview"] == photo


def prepare_env(monkeypatch, root):
    monkeypatch.setattr("sys.argv", ["prepare_local_test", "--state-root", str(root)])
    prepare_main()
    config = json.loads((root / "local-config.json").read_text(encoding="utf-8"))
    for key, value in config.items():
        monkeypatch.setenv(key, value)


def test_seed_and_port_config_are_persistent(monkeypatch, tmp_path, capsys):
    prepare_env(monkeypatch, tmp_path)
    files = ("v1-hsm-seed.json", "staff-hsms.json", "tp-staff.json", "local-config.json")
    before = {name: (tmp_path / name).read_bytes() for name in files}
    prepare_env(monkeypatch, tmp_path)
    assert all((tmp_path / name).read_bytes() == value for name, value in before.items())
    assert "Local test-adapter" in capsys.readouterr().out


def test_existing_local_config_gains_reviewer_seed_path(monkeypatch, tmp_path):
    prepare_env(monkeypatch, tmp_path)
    config_path = tmp_path / "local-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.pop("TPAA_LOCAL_REVIEWER_HSM_SEED")
    config_path.write_text(json.dumps(config), encoding="utf-8")

    prepare_env(monkeypatch, tmp_path)

    updated = json.loads(config_path.read_text(encoding="utf-8"))
    assert updated["TPAA_LOCAL_REVIEWER_HSM_SEED"] == str(tmp_path / "staff-hsms.json")


def test_tp_ap_review_phc_health_paths(monkeypatch, tmp_path):
    prepare_env(monkeypatch, tmp_path)
    monkeypatch.delenv("TPAA_LOCAL_REVIEWER_AUTH", raising=False)
    from services.local_test_stack import build_stack

    client = TestClient(build_stack().app, client=("127.0.0.1", 12345))
    expected = {
        "/healthz": "test-adapter",
        "/tp/healthz": "identity-service",
        "/ap/healthz": "agent-service",
        "/review/healthz": "review-service",
        "/phc/healthz": "phc-service",
        "/supervision/healthz": "supervision-service",
    }
    for path, name in expected.items():
        response = client.get(path)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload.get("service", payload.get("profile")) == name

    assert client.post("/local-demo/reviewer-session",
                       headers={"Origin": "http://127.0.0.1:5180"}).status_code == 404


def test_protocol_hsm_slots_persist_across_local_stack_rebuild(monkeypatch, tmp_path):
    prepare_env(monkeypatch, tmp_path)
    from services.local_test_stack import build_stack

    first = build_stack().app
    tp_app = next(route.app for route in first.routes if route.path == "/tp")
    ap_app = next(route.app for route in first.routes if route.path == "/ap")
    phc_app = next(route.app for route in first.routes if route.path == "/phc")
    first_supervision_n = phc_app.state.ctx.sup_pub.n
    object_cid = phc_app.state.ctx.storage.put(b"synthetic ciphertext", requester="test")
    tp_nonce, tp_pub = tp_app.state.ctx.tp_hsm.allocate_slot("tp-owner")
    ap_nonce, ap_pub = ap_app.state.ctx.ap_hsm.allocate_slot("ap-owner")

    second = build_stack().app
    tp_app = next(route.app for route in second.routes if route.path == "/tp")
    ap_app = next(route.app for route in second.routes if route.path == "/ap")
    phc_app = next(route.app for route in second.routes if route.path == "/phc")
    assert tp_app.state.ctx.tp_hsm.slot_public(tp_nonce) == tp_pub
    assert ap_app.state.ctx.ap_hsm.slot_public(ap_nonce) == ap_pub
    assert phc_app.state.ctx.sup_pub.n == first_supervision_n
    assert phc_app.state.ctx.storage.get(object_cid, requester="test") == b"synthetic ciphertext"


def test_local_reviewer_demo_uses_tp_auth_and_reviewer_role(monkeypatch, tmp_path):
    prepare_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TPAA_LOCAL_REVIEWER_AUTH", "1")
    monkeypatch.setenv("TPAA_LOCAL_REVIEWER_ORIGIN", "http://127.0.0.1:5180")
    from services.local_test_stack import build_stack

    app = build_stack().app
    route = "/local-demo/reviewer-session"
    remote_client = TestClient(app, client=("192.0.2.1", 12345))
    assert remote_client.post(
        route, headers={"Origin": "http://127.0.0.1:5180"}).status_code == 403
    client = TestClient(app, client=("127.0.0.1", 12345))
    assert client.post(route, headers={"Origin": "http://127.0.0.1:5173"}).status_code == 403

    result = client.post(route, headers={"Origin": "http://127.0.0.1:5180"})
    assert result.status_code == 200, result.text
    session = result.json()
    assert session["profile"] == "test-adapter"
    assert session["subject"] == "reviewer-a"
    assert session["role"] == "reviewer"

    queue = client.post("/tp/v1/applications/review-queue",
                        headers={"Authorization": f"Bearer {session['token']}"})
    assert queue.status_code == 200, queue.text
    assert queue.json() == {"items": []}

    phc_queue = client.get("/phc/v1/phc/reviewer-queue",
                           headers={"Authorization": f"Bearer {session['token']}"})
    assert phc_queue.status_code == 200, phc_queue.text
    assert phc_queue.json() == {"items": []}

    did_directory = client.get("/phc/v1/phc/did-directory",
                               headers={"Authorization": f"Bearer {session['token']}"})
    assert did_directory.status_code == 200, did_directory.text
    assert did_directory.json() == {"items": []}
    assert client.get("/phc/v1/phc/reviewer-queue").status_code == 401


def test_local_supervisor_demo_uses_distinct_ap_trusted_staff_keys(monkeypatch, tmp_path):
    prepare_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TPAA_LOCAL_REVIEWER_AUTH", "1")
    monkeypatch.setenv("TPAA_LOCAL_REVIEWER_ORIGIN", "http://127.0.0.1:5180")
    monkeypatch.setenv("TPAA_LOCAL_SUPERVISOR_AUTH", "1")
    monkeypatch.setenv("TPAA_LOCAL_SUPERVISOR_ORIGIN", "http://127.0.0.1:5180")
    from services.local_test_stack import build_stack

    app = build_stack().app
    route = "/local-demo/supervisor-session"
    remote_client = TestClient(app, client=("192.0.2.1", 12345))
    assert remote_client.post(
        route, json={"staffId": "supervisor-a"},
        headers={"Origin": "http://127.0.0.1:5180"}).status_code == 403
    client = TestClient(app, client=("127.0.0.1", 12345))
    wrong_origin = client.post(
        route, json={"staffId": "supervisor-a"},
        headers={"Origin": "http://127.0.0.1:5173"})
    assert wrong_origin.status_code == 403

    sessions = {}
    for staff_id in ("supervisor-a", "supervisor-b"):
        response = client.post(
            route, json={"staffId": staff_id},
            headers={"Origin": "http://127.0.0.1:5180"})
        assert response.status_code == 200, response.text
        sessions[staff_id] = response.json()
        assert sessions[staff_id]["subject"] == staff_id
        assert sessions[staff_id]["role"] == "supervisor"
    assert sessions["supervisor-a"]["token"] != sessions["supervisor-b"]["token"]

    agent_app = next(route.app for route in app.routes if route.path == "/ap")
    approval = client.post(
        "/local-demo/case-approval",
        json={"caseId": "case-demo", "did": "did:wba:demo:tp.local:ap.local",
              "purpose": "synthetic trace test"},
        headers={"Origin": "http://127.0.0.1:5180",
                 "Authorization": f"Bearer {sessions['supervisor-a']['token']}"})
    assert approval.status_code == 200, approval.text
    assert approval.json()["signPk"] in agent_app.state.ctx.supervisors
    reviewer = client.post(
        "/local-demo/reviewer-session", headers={"Origin": "http://127.0.0.1:5180"})
    assert reviewer.status_code == 200
    denied = client.post(
        "/local-demo/case-approval",
        json={"caseId": "case-demo", "did": "did:wba:demo:tp.local:ap.local",
              "purpose": "synthetic trace test"},
        headers={"Origin": "http://127.0.0.1:5180",
                 "Authorization": f"Bearer {reviewer.json()['token']}"})
    assert denied.status_code == 403
