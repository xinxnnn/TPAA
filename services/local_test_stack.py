"""A local HTTP stand-in for explicitly test-only local TPAA integration."""

from __future__ import annotations

import importlib
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import crypto.sdk
from fastapi import FastAPI, HTTPException, Request as FastAPIRequest

from localstore import Layout, ModuleRepo
from services.ipfs.storage_service.app import StorageService
from services.shared.store import JsonStore, JsonStoreMapping
from services.shared.v1_auth import AuthIssuer
from services.shared.v1_http import SystemClock, assert_single_worker, hsm_from_seed
from services.tp_side.identity_service.domain.usecases.intake import IdentityIntake
from services.tp_side.identity_service.infra.wiring import build_context as build_identity_context
from services.tp_side.review_service.domain.usecases.decide import ReviewDesk

v1 = crypto.sdk.v1


def _required(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"missing required local test-adapter setting: {name}")
    return value


class LocalDomainPort:
    """Portal's upstream HTTP contract pointed at the local adapter's mounted routes."""

    def __init__(self, base_url: str, auth_base_url: str, executor, user_sign_pk: str, service: str):
        self.base_url = base_url.rstrip("/")
        self.auth_base_url = auth_base_url.rstrip("/")
        self.executor = executor
        self.user_sign_pk = user_sign_pk
        self.service = service
        self.request_timeout = 120 if service in {"agent", "phc"} else 10
        self._token: str | None = None
        if urlsplit(self.base_url).hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("local test stack URLs must use loopback hosts")

    def _request_json(self, url: str, method: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(url, data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError(f"local {self.service} endpoint unavailable") from exc

    def _login(self) -> str:
        challenge = self._request_json(self.auth_base_url + "/v1/auth/challenge", "POST")
        signed = self.executor.login_body(challenge)
        if signed.get("signPk") != self.user_sign_pk or signed.get("challenge") != challenge.get("challenge"):
            raise RuntimeError("executor login body does not match local challenge")
        result = self._request_json(self.auth_base_url + "/v1/auth/login", "POST", signed)
        token = result.get("token")
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"local {self.service} login returned no bearer token")
        return token

    def _request(self, method: str, path: str, owner: str, body=None) -> dict:
        expected_owner = v1.owner_of(v1.pk_from_hex(self.user_sign_pk))
        if owner != expected_owner:
            raise PermissionError("local upstream request owner mismatch")
        if self._token is None:
            self._token = self._login()
        request = Request(self.base_url + path,
                          data=None if body is None else json.dumps(body).encode(),
                          method=method,
                          headers={"Authorization": f"Bearer {self._token}",
                                   "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.request_timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8"))
            message = payload.get("detail") or payload.get("message") or f"HTTP {exc.code}"
            if exc.code == 401 and method == "GET":
                self._token = self._login()
                return self._request(method, path, owner, body)
            if exc.code == 403:
                raise PermissionError(message) from exc
            if exc.code == 404:
                raise LookupError(message) from exc
            if exc.code == 409:
                from services.shared.v1_http import Conflict
                raise Conflict(message) from exc
            raise RuntimeError(f"local {self.service} returned HTTP {exc.code}: {message}") from exc
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"local {self.service} upstream unavailable") from exc

    def get(self, path: str) -> dict:
        return self._request("GET", path, v1.owner_of(v1.pk_from_hex(self.user_sign_pk)))

    def post(self, path: str, body: dict, owner: str) -> dict:
        return self._request("POST", path, owner, body)


@dataclass
class Stack:
    app: FastAPI
    tp_auth: AuthIssuer
    ap_auth: AuthIssuer
    reviewer_hsm: object


def build_stack(*, ap_assist=None) -> Stack:
    assert_single_worker("local-test-stack")
    root = Path(_required("TPAA_LOCAL_STATE_ROOT"))
    root.mkdir(parents=True, exist_ok=True)
    seed_env = "TPAA_V1_HSM_SEED"
    slots_root = root / "hsm-slots"
    tp_hsm = hsm_from_seed("TP", seed_env, bindings=JsonStoreMapping(slots_root / "tp.json"))
    ap_hsm = hsm_from_seed("AP", seed_env, bindings=JsonStoreMapping(slots_root / "ap.json"))
    review_hsm = hsm_from_seed("REVIEW", seed_env)
    auth_hsm = hsm_from_seed("AUTH", seed_env)
    seed_data = json.loads(Path(_required(seed_env)).read_text(encoding="utf-8"))
    ap_auth_hsm = v1.hsm_from_seed(domain="AUTH", seed=seed_data["ap_auth"])
    clock = SystemClock()
    staff = json.loads(Path(_required("TPAA_TP_STAFF")).read_text(encoding="utf-8"))
    tp_auth = AuthIssuer(issuer_hsm=auth_hsm, aud="tpaa:tp", clock=clock, staff=staff)
    ap_auth = AuthIssuer(issuer_hsm=ap_auth_hsm, aud="tpaa:ap", clock=clock)
    local_demo_staff_hsms = {}
    reviewer_seed_path = os.environ.get("TPAA_LOCAL_REVIEWER_HSM_SEED", "").strip()
    if reviewer_seed_path:
        reviewer_seeds = json.loads(Path(reviewer_seed_path).read_text(encoding="utf-8"))
        for staff_id in ("reviewer-a", "supervisor-a", "supervisor-b"):
            if staff_id not in reviewer_seeds:
                continue
            test_hsm = v1.hsm_from_seed(domain="STAFF", seed=reviewer_seeds[staff_id])
            test_pk = v1.pk_hex(test_hsm.pubkey())
            expected_role = "reviewer" if staff_id == "reviewer-a" else "supervisor"
            member = staff.get(test_pk, {})
            if member.get("id") != staff_id or member.get("role") != expected_role:
                raise RuntimeError(
                    f"local demo STAFF key {staff_id} is not registered with TP role {expected_role}")
            local_demo_staff_hsms[staff_id] = test_hsm
    local_reviewer_hsm = local_demo_staff_hsms.get("reviewer-a")

    ap_root = Path(_required("TPAA_STORE_ROOT"))
    ap_root.mkdir(parents=True, exist_ok=True)
    modules = ModuleRepo(Layout(ap_root))
    for module_id, code in (("summarize", b"def run(text):\n    return text[:80]\n"),
                            ("translate", b"def run(text, language):\n    return text\n")):
        if "1.0.0" not in modules.versions(module_id):
            modules.publish(module_id, "1.0.0", {"engine.py": code})
    try:
        index_key = bytes.fromhex(_required("TPAA_INDEX_KEY"))
        ecid_key = bytes.fromhex(_required("TPAA_ECID_KEY"))
    except ValueError as exc:
        raise RuntimeError("local AP index and ECID keys must be hex") from exc
    if len(index_key) < 32 or len(ecid_key) < 32:
        raise RuntimeError("local AP index and ECID keys must each contain at least 32 bytes")

    agent_service = importlib.import_module("services.ap_side.agent_service.v1_app")
    identity_service = importlib.import_module("services.tp_side.identity_service.app")
    review_service = importlib.import_module("services.tp_side.review_service.app")
    phc_service = importlib.import_module("services.tp_side.phc_service.app")

    try:
        supervision_seed = bytes.fromhex(seed_data["supervision"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("local supervision key seed is missing or invalid") from exc
    sup_key = crypto.sdk.make_supervision_key(bits=2048, seed=supervision_seed)
    agent_ctx = agent_service.build_context(
        ap_hsm=ap_hsm, modules=modules, tp_sign_pk=tp_hsm.pubkey(), sup_pub=sup_key.public(),
        domain2=os.environ.get("TPAA_AP_DOMAIN", "ap.local"), db_path=str(root / "agent.json"),
        clock=clock, supervisors={pk for pk, member in staff.items()
                                  if member.get("role") == "supervisor"}, tp_enc_pk=tp_hsm.enc_pub(),
        runtime_tp_hsm=tp_hsm)
    ap = agent_service.create_app(ctx=agent_ctx, auth=ap_auth)
    ap_keys = {"signPk": v1.pk_hex(ap_hsm.pubkey()),
               "chameleonCpk": crypto.sdk.ser_point(ap_hsm.chameleon_cpk()).hex(),
               "encPub": format(ap_hsm.enc_pub(), "x")}

    identity_ctx = build_identity_context(
        tp_hsm=tp_hsm, db_path=str(root / "identity.json"), clock=clock,
        demo_photo_preview=True, test_adapter=True)
    intake = IdentityIntake(identity_ctx)
    identity_state = identity_ctx.store.load()
    metadata_migrated = False
    for application in identity_state.get("apps", {}).values():
        opened = v1.tp.tp_open_cr(tp_hsm=tp_hsm, cr_box=application["crBox"],
                                  now=application["receivedAt"], recover_missing_slot=True)
        if not intake.has_review_metadata(application.get("reviewMetadata")):
            application["reviewMetadata"] = intake.review_metadata(opened)
            metadata_migrated = True
    if metadata_migrated:
        identity_ctx.store.save(identity_state)
    identity = identity_service.create_app(ctx=identity_ctx, auth=tp_auth)
    review_ctx = review_service.build_context(
        review_hsm=review_hsm, identity=intake, db_path=str(root / "review.json"), clock=clock)
    review_desk = ReviewDesk(review_ctx)
    identity_ctx.review = review_desk
    review = review_service.create_app(ctx=review_ctx, verifier=tp_auth.verifier())
    storage = StorageService(state_path=root / "storage.json")
    phc_ctx = phc_service.build_context(
        tp_hsm=tp_hsm, identity=intake, review=review_desk, review_pk=review_hsm.pubkey(),
        sup_pub=sup_key.public(), storage=storage, ap_bundle=ap_keys,
        domain1=os.environ.get("TPAA_TP_DOMAIN", "tp.local"), db_path=str(root / "phc.json"),
        clock=clock, allow_demo_scid_reveal=True)
    phc = phc_service.create_app(ctx=phc_ctx, verifier=tp_auth.verifier())
    supervision_service = importlib.import_module(
        "services.tp_side.supervision_service.v1_app")
    if ap_assist is None:
        def ap_assist(req):
            url = _required("TPAA_LOCAL_TEST_STACK_URL").rstrip("/") + "/ap/v1/tpaa/assist"
            request = Request(url, data=json.dumps({"req": req}).encode("utf-8"),
                              method="POST", headers={"Content-Type": "application/json"})
            try:
                with urlopen(request, timeout=30) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"local AP rejected the trace assist request (HTTP {exc.code}): {detail}") from exc
            except (URLError, TimeoutError) as exc:
                raise RuntimeError("local AP trace assist endpoint unavailable") from exc
            answer = payload.get("answer")
            if not isinstance(answer, dict):
                raise RuntimeError("local AP trace assist returned no sealed answer")
            return answer

    supervision_db_path = root / "supervision.json"
    supervision_store = JsonStore(supervision_db_path)
    supervision_state = supervision_store.load()
    if "legacyDids" not in supervision_state:
        supervision_state["legacyDids"] = [
            item["did"] for item in phc.state.desk.did_directory()["items"]
        ]
        supervision_state.setdefault("cases", {})
        supervision_store.save(supervision_state)
    legacy_dids = supervision_state["legacyDids"]
    if not isinstance(legacy_dids, list) or not all(isinstance(did, str) for did in legacy_dids):
        raise RuntimeError("local supervision state has an invalid legacyDids list")

    def open_local_forensic(staff_id: str, box: dict) -> dict:
        staff_hsm = local_demo_staff_hsms.get(staff_id)
        if staff_hsm is None:
            raise HTTPException(status_code=403, detail="该监管员没有本地演示取证解密密钥")
        return v1.case.open_forensic(staff_hsm, box)

    supervision_ctx = supervision_service.build_context(
        tp_hsm=tp_hsm, sup_key=sup_key, records=phc.state.desk, storage=phc_ctx.storage,
        ap_assist=ap_assist, staff=staff, db_path=str(supervision_db_path), clock=clock,
        legacy_dids=set(legacy_dids), forensic_open=open_local_forensic)
    supervision = supervision_service.create_app(
        ctx=supervision_ctx, verifier=tp_auth.verifier())

    combined = FastAPI(title="TPAA local test-adapter stack")
    combined.state.profile = "test-adapter"
    combined.state.tp_auth = tp_auth
    combined.state.ap_auth = ap_auth
    combined.state.staff_directory = staff
    combined.state.reviewer_hsm = review_hsm
    combined.state.supervisor_hsms = {
        staff_id: hsm for staff_id, hsm in local_demo_staff_hsms.items()
        if staff_id.startswith("supervisor-")}
    combined.mount("/tp", identity)
    combined.mount("/review", review)
    combined.mount("/phc", phc)
    combined.mount("/supervision", supervision)
    combined.mount("/ap", ap)

    @combined.get("/healthz")
    def healthz():
        return {"status": "ok", "profile": "test-adapter",
                "services": ["identity", "review", "phc", "agent", "supervision"]}

    @combined.get("/ap/healthz", include_in_schema=False)
    def ap_healthz():
        return {"status": "ok", "service": "agent-service", "profile": "tpaa_v1"}

    @combined.get("/review/healthz", include_in_schema=False)
    def review_healthz():
        return {"status": "ok", "service": "review-service", "profile": "tpaa_v1"}

    @combined.get("/phc/healthz", include_in_schema=False)
    def phc_healthz():
        return {"status": "ok", "service": "phc-service", "profile": "tpaa_v1"}

    @combined.post("/local-demo/reviewer-session")
    def local_reviewer_session(request: FastAPIRequest):
        if (os.environ.get("TPAA_LOCAL_REVIEWER_AUTH") != "1"
                or local_reviewer_hsm is None):
            raise HTTPException(status_code=404, detail="local reviewer demo is disabled")
        allowed_origin = os.environ.get(
            "TPAA_LOCAL_REVIEWER_ORIGIN", "http://127.0.0.1:5180").rstrip("/")
        client_host = request.client.host if request.client else ""
        try:
            is_loopback = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise HTTPException(status_code=403, detail="local reviewer demo is loopback-only")
        if request.headers.get("origin", "").rstrip("/") != allowed_origin:
            raise HTTPException(status_code=403, detail="Origin mismatch")

        challenge = tp_auth.challenge()
        signed = {
            "challenge": challenge["challenge"],
            "signPk": v1.pk_hex(local_reviewer_hsm.pubkey()),
            "sig": v1.auth.sign_login(local_reviewer_hsm, challenge=challenge["challenge"],
                                      aud=challenge["aud"]),
        }
        login = tp_auth.login(challenge=signed["challenge"],
                              sign_pk=signed["signPk"], sig=signed["sig"])
        if login["role"] != "reviewer" or login["sub"] != "reviewer-a":
            raise RuntimeError("local demo reviewer key did not resolve to the reviewer role")
        return {"profile": "test-adapter", "subject": login["sub"], "role": login["role"],
                "token": login["token"], "expires": login["expires"]}

    @combined.post("/local-demo/supervisor-session")
    def local_supervisor_session(body: dict, request: FastAPIRequest):
        if os.environ.get("TPAA_LOCAL_SUPERVISOR_AUTH") != "1":
            raise HTTPException(status_code=404, detail="local supervisor demo is disabled")
        client_host = request.client.host if request.client else ""
        try:
            is_loopback = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise HTTPException(status_code=403, detail="local supervisor demo is loopback-only")
        allowed_origin = os.environ.get(
            "TPAA_LOCAL_SUPERVISOR_ORIGIN", "http://127.0.0.1:5180").rstrip("/")
        if request.headers.get("origin", "").rstrip("/") != allowed_origin:
            raise HTTPException(status_code=403, detail="Origin mismatch")

        staff_id = body.get("staffId")
        if not isinstance(staff_id, str) or not staff_id.startswith("supervisor-"):
            raise HTTPException(status_code=400, detail="unknown local demo supervisor")
        hsm = local_demo_staff_hsms.get(staff_id)
        if hsm is None:
            raise HTTPException(status_code=400, detail="unknown local demo supervisor")
        challenge = tp_auth.challenge()
        signed = {
            "challenge": challenge["challenge"],
            "signPk": v1.pk_hex(hsm.pubkey()),
            "sig": v1.auth.sign_login(hsm, challenge=challenge["challenge"], aud=challenge["aud"]),
        }
        login = tp_auth.login(challenge=signed["challenge"],
                              sign_pk=signed["signPk"], sig=signed["sig"])
        if login["role"] != "supervisor" or login["sub"] != staff_id:
            raise RuntimeError("local demo STAFF key did not resolve to the supervisor role")
        return {"profile": "test-adapter", "subject": login["sub"], "role": login["role"],
                "token": login["token"], "expires": login["expires"]}

    @combined.post("/local-demo/case-approval")
    def local_case_approval(body: dict, request: FastAPIRequest):
        if os.environ.get("TPAA_LOCAL_SUPERVISOR_AUTH") != "1":
            raise HTTPException(status_code=404, detail="local supervisor demo is disabled")
        client_host = request.client.host if request.client else ""
        try:
            is_loopback = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise HTTPException(status_code=403, detail="local supervisor demo is loopback-only")
        allowed_origin = os.environ.get(
            "TPAA_LOCAL_SUPERVISOR_ORIGIN", "http://127.0.0.1:5180").rstrip("/")
        if request.headers.get("origin", "").rstrip("/") != allowed_origin:
            raise HTTPException(status_code=403, detail="Origin mismatch")
        try:
            claims = tp_auth.verifier().check(request.headers.get("authorization"))
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        staff_id = claims.get("sub", "")
        hsm = local_demo_staff_hsms.get(staff_id)
        if claims.get("role") != "supervisor" or hsm is None:
            raise HTTPException(status_code=403, detail="a local supervisor session is required")
        from crypto.tpaa_v1.case import sign_case_approval

        case_id, did, purpose = body.get("caseId"), body.get("did"), body.get("purpose")
        if not all(isinstance(value, str) and value.strip()
                   for value in (case_id, did, purpose)):
            raise HTTPException(status_code=400, detail="caseId, did and purpose are required")
        return sign_case_approval(hsm, case_id=case_id, did=did, purpose=purpose)

    return Stack(combined, tp_auth, ap_auth, review_hsm)


def create_app() -> FastAPI:
    return build_stack().app


class _LocalStackApp:
    """Lazy ASGI wrapper so uvicorn can import without building keys at import time."""

    def __init__(self):
        self._inner: FastAPI | None = None

    def _get(self) -> FastAPI:
        if self._inner is None:
            self._inner = create_app()
        return self._inner

    async def __call__(self, scope, receive, send):
        await self._get()(scope, receive, send)


app = _LocalStackApp()
