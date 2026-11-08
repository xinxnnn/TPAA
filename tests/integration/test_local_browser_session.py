from __future__ import annotations

import crypto.sdk
from fastapi.testclient import TestClient

from services.shared.store import JsonStore
from services.shared.v1_auth import AuthIssuer
from services.shared.v1_http import FixedClock
from services.user_side.portal_api.app import DomainPort, PortalContext, create_app


ORIGIN = "http://127.0.0.1:5173"


def _app(tmp_path, *, profile: str = "test-adapter"):
    user_hsm = crypto.sdk.v1.make_demo_hsm(domain="USER")
    public_key = crypto.sdk.v1.pk_hex(user_hsm.pubkey())
    owner = crypto.sdk.v1.owner_of(user_hsm.pubkey())

    class Executor:
        def public_signing_key(self):
            return public_key

    tp_keys = {"encPub": "11", "signPk": public_key, "chameleonCpk": "22"}
    ap_keys = {"encPub": "33", "signPk": public_key, "chameleonCpk": "44"}
    supervision_n = (1 << 2047) + 1

    def tp_get(path):
        assert path == "/v1/keys"
        return tp_keys

    def ap_get(path):
        assert path == "/v1/tpaa/keys"
        return ap_keys

    def phc_get(path):
        assert path == "/v1/phc/keys"
        return {"paillier": {"n": format(supervision_n, "x"),
                             "g1": format(supervision_n + 1, "x")},
                "purpose": "supervision-irf-ecid"}

    def unexpected(*_args):
        raise AssertionError("initialization must not mutate domain services")

    clock = FixedClock()
    ctx = PortalContext(
        wallet_root=tmp_path / "wallet",
        store=JsonStore(tmp_path / "portal.json"),
        tp=DomainPort(tp_get, unexpected),
        ap=DomainPort(ap_get, unexpected),
        phc=DomainPort(phc_get, unexpected),
        agent=DomainPort(ap_get, unexpected),
        auth=AuthIssuer(issuer_hsm=crypto.sdk.v1.make_demo_hsm(domain="AUTH"),
                        aud="tpaa:user", clock=clock),
        clock=clock,
        handlers={owner: Executor()},
        execution_profile=profile,
    )
    return create_app(ctx=ctx)


def test_local_demo_session_starts_and_revokes(tmp_path, monkeypatch):
    monkeypatch.setenv("TPAA_LOCAL_TEST_AUTH", "1")
    with TestClient(_app(tmp_path)) as client:
        status = client.get("/api/user/v1/local-session")
        assert status.status_code == 200
        assert status.json() == {"enabled": True, "authenticated": False,
                                 "owner": None, "profile": "test-adapter",
                                 "userControlledExecution": False}

        started = client.post("/api/user/v1/local-session", json={}, headers={"Origin": ORIGIN})
        assert started.status_code == 200, started.text
        assert started.json()["enabled"] is True
        assert started.json()["profile"] == "test-adapter"
        assert started.json()["userControlledExecution"] is False
        assert started.json()["identity"].startswith("local test-adapter identity")
        assert client.cookies.get("tpaa_local_test_session")
        initialized = client.get("/api/user/v1/initialize")
        assert initialized.status_code == 200
        assert initialized.json()["owner"] == started.json()["owner"]
        assert initialized.json()["publicKeys"]["user"]["pk"] == initialized.json()["userSignPk"]

        ended = client.delete("/api/user/v1/local-session", headers={"Origin": ORIGIN})
        assert ended.status_code == 200
        assert ended.json() == {"loggedOut": True}
        assert client.get("/api/user/v1/initialize").status_code == 401


def test_local_demo_session_rejects_bad_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("TPAA_LOCAL_TEST_AUTH", "1")
    with TestClient(_app(tmp_path)) as client:
        response = client.post("/api/user/v1/local-session", json={},
                               headers={"Origin": "https://attacker.example"})
        assert response.status_code == 403
        assert client.cookies.get("tpaa_local_test_session") is None


def test_local_demo_session_is_not_available_outside_test_adapter(tmp_path, monkeypatch):
    monkeypatch.setenv("TPAA_LOCAL_TEST_AUTH", "1")
    with TestClient(_app(tmp_path, profile="production")) as client:
        response = client.post("/api/user/v1/local-session", json={}, headers={"Origin": ORIGIN})
        assert response.status_code == 404


def test_local_demo_session_is_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("TPAA_LOCAL_TEST_AUTH", raising=False)
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/api/user/v1/local-session").json() == {
            "enabled": False, "authenticated": False, "owner": None}
        response = client.post("/api/user/v1/local-session", json={}, headers={"Origin": ORIGIN})
        assert response.status_code == 404
