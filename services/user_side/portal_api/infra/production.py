from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import crypto.sdk
from services.shared.store import JsonStore
from services.shared.v1_auth import AuthIssuer
from services.shared.v1_http import Conflict, Forbidden, NotFound, env_required, hsm_from_seed
from services.user_side.portal_api.app import PortalContext


class ServiceHttpPort:
    def __init__(self, base_url: str, auth_base_url: str, executor, user_sign_pk: str, service: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_base_url = auth_base_url.rstrip("/")
        self.executor = executor
        self.user_sign_pk = user_sign_pk
        self.service = service
        self._token: str | None = None

    def _request_json(self, url: str, method: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(url, data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
                message = payload.get("detail") or payload.get("message")
            except (ValueError, UnicodeDecodeError):
                message = None
            message = message or f"上游 {self.service} 返回 HTTP {exc.code}"
            if exc.code == 403:
                raise Forbidden(message) from exc
            raise RuntimeError(message) from exc
        except (TimeoutError, URLError) as exc:
            raise RuntimeError(f"上游 {self.service} 暂不可用") from exc

    def _login(self) -> str:
        challenge = self._request_json(self.auth_base_url + "/v1/auth/challenge", "POST")
        signed = self.executor.login_body(challenge)
        if signed.get("signPk") != self.user_sign_pk or signed.get("challenge") != challenge.get("challenge"):
            raise Forbidden("执行器登录响应与挑战或用户公钥不一致")
        result = self._request_json(self.auth_base_url + "/v1/auth/login", "POST", signed)
        token = result.get("token")
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"上游 {self.service} 登录未返回令牌")
        return token

    def _request(self, method: str, path: str, owner: str, body: dict | None = None) -> dict:
        expected_owner = crypto.sdk.v1.owner_of(crypto.sdk.v1.pk_from_hex(self.user_sign_pk))
        if owner != expected_owner:
            raise Forbidden("上游请求归属人与当前用户不符")
        if self._token is None:
            self._token = self._login()
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(self.base_url + path, data=data, method=method,
                          headers={"Authorization": f"Bearer {self._token}",
                                   "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
                message = payload.get("detail") or payload.get("message")
            except (ValueError, UnicodeDecodeError):
                message = None
            message = message or f"上游 {self.service} 返回 HTTP {exc.code}"
            if exc.code == 401 and method == "GET":
                self._token = self._login()
                return self._request(method, path, owner, body)
            if exc.code == 403:
                raise Forbidden(message) from exc
            if exc.code == 404:
                raise NotFound(message) from exc
            if exc.code == 409:
                raise Conflict(message) from exc
            if exc.code == 413:
                raise RuntimeError(f"上游 {self.service} 请求超限（HTTP 413）：{message}") from exc
            raise RuntimeError(message) from exc
        except (TimeoutError, URLError) as exc:
            raise RuntimeError(f"上游 {self.service} 暂不可用") from exc

    def get(self, path: str) -> dict:
        return self._request("GET", path, crypto.sdk.v1.owner_of(
            crypto.sdk.v1.pk_from_hex(self.user_sign_pk)))

    def post(self, path: str, body: dict, owner: str) -> dict:
        return self._request("POST", path, owner, body)



def build_context(*, clock):
    """Assemble the portal using the explicit local test adapter or deployment HTTP ports."""
    from services.user_side.portal_api.infra.executor_http import ExecutorHttpClient

    executor = ExecutorHttpClient(env_required("TPAA_EXECUTOR_URL"),
                                  env_required("TPAA_EXECUTOR_TOKEN"),
                                  env_required("TPAA_EXECUTOR_OWNER"))
    user_sign_pk = executor.public_signing_key()
    if crypto.sdk.v1.owner_of(crypto.sdk.v1.pk_from_hex(user_sign_pk)) != executor.owner:
        raise RuntimeError("executor signing key does not match configured owner")
    user_auth = AuthIssuer(issuer_hsm=hsm_from_seed("AUTH", "TPAA_USER_AUTH_HSM_SEED"),
                           aud="tpaa:user", clock=clock)
    if os.environ.get("TPAA_LOCAL_TEST_STACK") == "1":
        from services.local_test_stack import LocalDomainPort

        stack_url = env_required("TPAA_LOCAL_TEST_STACK_URL", "http://127.0.0.1:8120").rstrip("/")
        tp = LocalDomainPort(stack_url + "/tp", stack_url + "/tp", executor, user_sign_pk, "tp")
        ap = LocalDomainPort(stack_url + "/ap", stack_url + "/ap", executor, user_sign_pk, "ap")
        phc = LocalDomainPort(stack_url + "/phc", stack_url + "/tp", executor, user_sign_pk, "phc")
    else:
        tp_url = env_required("TPAA_TP_URL")
        ap_url = env_required("TPAA_AP_URL")
        tp = ServiceHttpPort(tp_url, env_required("TPAA_TP_AUTH_URL", tp_url), executor,
                             user_sign_pk, "tp")
        ap = ServiceHttpPort(ap_url, env_required("TPAA_AP_AUTH_URL", ap_url), executor,
                             user_sign_pk, "ap")
        phc_url = env_required("TPAA_PHC_URL")
        phc = ServiceHttpPort(phc_url, env_required("TPAA_PHC_AUTH_URL", tp_url), executor,
                              user_sign_pk, "phc")
    return PortalContext(wallet_root=Path(env_required("TPAA_USER_STATE_ROOT")),
                         store=JsonStore(env_required("TPAA_USER_WORKFLOW_DB")),
                         tp=tp, ap=ap, phc=phc, agent=ap, auth=user_auth, clock=clock,
                         handlers={executor.owner: executor}, execution_profile="test-adapter")


__all__ = ["ServiceHttpPort", "build_context"]
