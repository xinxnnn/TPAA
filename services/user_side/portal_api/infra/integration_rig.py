from __future__ import annotations

import crypto.sdk

from services.shared.v1_http import Forbidden, NotFound
from services.shared.v1_auth import AuthIssuer


class IntegrationRig:
    """Build user-workflow dependencies over the existing service test rig ports."""

    def __init__(self, root, clock, user_hsm, tp_app, ap_app, phc_app, identity_app, review_app,
                 tp_auth, ap_auth):
        from pathlib import Path

        from fastapi.testclient import TestClient
        from services.shared.store import JsonStore
        from services.shared.v1_auth import AuthIssuer
        import crypto.sdk

        self.root = Path(root)
        self.clock = clock
        self.user_hsm = user_hsm
        self.tp_app = tp_app
        self.ap_app = ap_app
        self.phc_app = phc_app
        self.identity_app = identity_app
        self.review_app = review_app
        self.tp = TestClient(tp_app)
        self.ap = TestClient(ap_app)
        self.phc = TestClient(phc_app)
        self.identity = TestClient(identity_app)
        self.tp_auth = tp_auth
        self.ap_auth = ap_auth
        from user_credential_handler import UserCredentialHandler
        self.portal_handlers = {crypto_owner(user_hsm): UserCredentialHandler(
            self.root / "portal-handlers" / "default", hsm=user_hsm)}
        self.user_auth = AuthIssuer(issuer_hsm=crypto.sdk.v1.make_demo_hsm(domain="AUTH"),
                                    aud="tpaa:user", clock=clock)
        self._tokens = {}

    def _user_token(self, owner: str) -> str:
        if owner != crypto_owner(self.user_hsm):
            raise Forbidden("user workflow owner does not match credential-handler key")
        if owner not in self._tokens:
            self._tokens[owner] = self.user_auth.token_for(self.user_hsm.sign_pk_hex)["token"]
        return self._tokens[owner]

    def _upstream_token(self, service: str, owner: str) -> str:
        signer = crypto.sdk.v1.pk_hex(self.user_hsm.pubkey())
        if owner != crypto.sdk.v1.owner_of(self.user_hsm.pubkey()):
            raise Forbidden("upstream owner does not match credential key")
        auth = self.tp_auth if service in ("tp", "phc") else self.ap_auth
        return auth.token_for(signer)["token"]

    def _request(self, client, method: str, path: str, owner: str, body=None, *, service: str):
        headers = {"Authorization": f"Bearer {self._upstream_token(service, owner)}"}
        response = client.request(method, path, json=body, headers=headers)
        if response.status_code >= 400:
            payload = response.json()
            status = response.status_code
            message = payload.get("message", response.text)
            if status == 404:
                raise NotFound(message)
            if status == 403:
                raise Forbidden(message)
            raise RuntimeError(f"{method} {path}: {status}: {message}")
        return response.json()

    def domain_port(self, service: str):
        from services.user_side.portal_api.app import DomainPort
        clients = {"tp": self.identity, "ap": self.ap, "phc": self.phc, "agent": self.ap}
        client = clients[service]
        return DomainPort(
            get_fn=lambda path: self._request(client, "GET", path, crypto_owner(self.user_hsm), service=service),
            post_fn=lambda path, body, owner: self._request(client, "POST", path, owner, body, service=service))

    def portal_context(self, db_path, wallet_root):
        from services.shared.store import JsonStore
        from services.user_side.portal_api.app import PortalContext
        from services.user_side.portal_api.infra.executor_http import _TestExecutorHttpClient
        from services.user_side.executor_service.app import ExecutorContext, create_app as create_executor_app
        from fastapi.testclient import TestClient

        owner = crypto_owner(self.user_hsm)
        handler = self.portal_handlers[owner]
        executor_app = create_executor_app(ctx=ExecutorContext(
            handler=handler, token="integration-executor-token"))
        executor_client = TestClient(executor_app)
        remote_executor = _TestExecutorHttpClient(
            executor_client, "integration-executor-token", owner, handler)
        return PortalContext(wallet_root=wallet_root, store=JsonStore(db_path),
                             tp=self.domain_port("tp"), ap=self.domain_port("ap"),
                             phc=self.domain_port("phc"), agent=self.domain_port("agent"),
                             auth=self.user_auth, clock=self.clock,
                             handlers={owner: remote_executor}, execution_profile="test-adapter-http")


def crypto_owner(hsm) -> str:
    import crypto.sdk
    return crypto.sdk.v1.owner_of(hsm.pubkey())


__all__ = ["IntegrationRig", "crypto_owner"]
