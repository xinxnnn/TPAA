"""HTTP client for the loopback-only test executor."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class ExecutorHttpClient:
    def __init__(self, base_url: str, token: str, owner: str, *, timeout: float = 5.0) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("test executor URL must use HTTP loopback")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.owner = owner
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(self.base_url + path, data=data, method=method,
                          headers={"Authorization": f"Bearer {self.token}",
                                   "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
                message = payload.get("detail") or payload.get("message") or "executor request failed"
            except (ValueError, UnicodeDecodeError):
                message = "executor request failed"
            raise RuntimeError(f"user executor returned HTTP {exc.code}: {message}") from exc
        except (TimeoutError, URLError) as exc:
            raise RuntimeError("user executor unavailable") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("user executor returned an invalid response")
        return payload

    def public_signing_key(self) -> str:
        value = self._request("GET", "/v1/executor/public-key")
        if value.get("owner") != self.owner:
            raise RuntimeError("executor key is not bound to configured owner")
        return value["signPk"]

    def custody_profile(self) -> str:
        value = self._request("GET", "/v1/executor/public-key")
        if value.get("owner") != self.owner:
            raise RuntimeError("executor key is not bound to configured owner")
        if value.get("profile") == "user-controlled" and value.get("userControlledExecution") is True:
            return "user-controlled"
        return "test-adapter"

    def login_body(self, challenge: dict) -> dict:
        return self._request("POST", "/v1/executor/login-body", {"challenge": challenge})

    def build_cr(self, *, label: str, owner: str, **kwargs) -> dict:
        if owner != self.owner:
            raise PermissionError("executor owner mismatch")
        return self._request("POST", "/v1/executor/build-cr",
                             {"label": label, "owner": owner, **kwargs})["cr"]

    # 改状态的操作：服务端要求 requestId 并按它做幂等。
    MUTATING = {"set-application", "accept-rr", "accept-g4", "build-ar", "open-cmm",
                "build-paci", "accept-par", "build-didgr", "verify-final", "accept-final"}

    def _request_id(self, operation: str, label: str, application_id: str | None) -> str:
        """稳定派生，而不是每次随机。

        ★ 随机号会让幂等失效：重试拿到新号，服务端当成另一次请求照做一遍。
          流程里每个操作对一张申请只做一次，所以"同申请同操作"就是重试语义。
        """
        return f"{application_id or label}:{operation}"

    def _call(self, operation: str, label: str, *, owner: str, application_id: str | None = None,
              request_id: str | None = None, **kwargs) -> dict:
        if owner != self.owner:
            raise PermissionError("executor owner mismatch")
        body = {"label": label, "owner": owner, **kwargs}
        if operation in self.MUTATING:
            body["requestId"] = request_id or self._request_id(operation, label, application_id)
        if application_id is not None:
            bound = self.application_id(label)
            if bound != application_id:
                raise PermissionError("executor application mismatch")
            body["applicationId"] = application_id
        return self._request("POST", f"/v1/executor/{operation}", body)

    def set_application(self, label: str, app_id: str, *, owner: str) -> None:
        if owner != self.owner:
            raise PermissionError("executor owner mismatch")
        self._call("set-application", label, owner=owner, appId=app_id)
        if self.application_id(label) != app_id:
            raise RuntimeError("executor application binding was not persisted")

    def _application(self, label: str, owner: str) -> str:
        if owner != self.owner:
            raise PermissionError("executor owner mismatch")
        app_id = self.application_id(label)
        if app_id is None:
            raise RuntimeError("executor label has no application binding")
        return app_id

    def accept_rr(self, label: str, rr: dict, *, owner: str, application_id: str | None = None) -> dict:
        return self._call("accept-rr", label, owner=owner,
                          application_id=application_id or self._application(label, owner), rr=rr)

    def accept_g4(self, label: str, *, owner: str, application_id: str | None = None) -> dict:
        return self._call("accept-g4", label, owner=owner,
                          application_id=application_id or self._application(label, owner))

    def build_ar(self, label: str, *, expires: str, owner: str,
                 application_id: str | None = None) -> dict:
        return self._call("build-ar", label, owner=owner,
                          application_id=application_id or self._application(label, owner), expires=expires)

    def open_cmm(self, label: str, cmm_box: dict, *, owner: str,
                 application_id: str | None = None) -> dict:
        return self._call("open-cmm", label, owner=owner,
                          application_id=application_id or self._application(label, owner), cmm=cmm_box)

    def build_paci(self, label: str, *, selection: list[dict], owner: str,
                   application_id: str | None = None) -> dict:
        return self._call("build-paci", label, owner=owner,
                          application_id=application_id or self._application(label, owner), selection=selection)

    def accept_par(self, label: str, par: dict, *, owner: str,
                   application_id: str | None = None) -> dict:
        return self._call("accept-par", label, owner=owner,
                          application_id=application_id or self._application(label, owner), par=par)

    def build_didgr(self, label: str, *, expires: str, owner: str,
                    application_id: str | None = None) -> dict:
        return self._call("build-didgr", label, owner=owner,
                          application_id=application_id or self._application(label, owner), expires=expires)

    def verify_final(self, label: str, final: dict, finalization_attestation: dict, *, owner: str,
                     application_id: str | None = None) -> dict:
        return self._call("verify-final", label, owner=owner,
                          application_id=application_id or self._application(label, owner),
                          final=final, attestation=finalization_attestation)

    def accept_final(self, label: str, *, owner: str, application_id: str | None = None) -> dict:
        return self._call("accept-final", label, owner=owner,
                          application_id=application_id or self._application(label, owner))

    def publication_receipt(self, label: str, *, owner: str,
                           application_id: str | None = None) -> dict:
        return self._call("publication-receipt", label, owner=owner,
                          application_id=application_id or self._application(label, owner))

    def credential(self, label: str, *, owner: str, application_id: str | None = None) -> dict:
        return self._call("credential", label, owner=owner,
                          application_id=application_id or self._application(label, owner))

    def application_id(self, label: str) -> str | None:
        value = self._request("GET", f"/v1/executor/{label}/application")
        app_id = value.get("applicationId")
        return app_id if isinstance(app_id, str) and app_id else None

    def pending_request(self, label: str, *, owner: str) -> dict:
        return self._call("pending-request", label, owner=owner, application_id=self._application(label, owner))

    def events(self, label: str, *, owner: str, application_id: str | None = None) -> list[dict]:
        return self._call("events", label, owner=owner, application_id=application_id)["events"]


class _TestExecutorHttpClient(ExecutorHttpClient):
    """Transport shim letting IntegrationRig use TestClient over the same contract."""

    def __init__(self, client, token: str, owner: str, handler=None) -> None:
        self.client = client
        self.token = token
        self.owner = owner

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        response = self.client.request(method, path, json=body,
                                       headers={"Authorization": f"Bearer {self.token}"})
        if response.status_code >= 400:
            payload = response.json()
            message = payload.get("detail") or payload.get("message") or "executor request failed"
            raise RuntimeError(f"user executor returned HTTP {response.status_code}: {message}")
        return response.json()


__all__ = ["ExecutorHttpClient", "_TestExecutorHttpClient"]
