"""Loopback-only test executor for user-side tpaa_v1 operations.

This service is a process-isolation test adapter, not production key custody.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass

from fastapi import Body, FastAPI, Header, HTTPException, Request

from services.shared.v1_http import (Conflict, LazyApp, assert_single_worker, env_required,
                                     install_errors)
from user_credential_handler.handler import CredentialHandlerError


@dataclass
class ExecutorContext:
    handler: object
    token: str
    profile: str = "test-adapter"


MAX_BODY_BYTES = 256 * 1024

# 每个操作的信封字段：label / owner 必填，applicationId 与 requestId 按下表要求。
_ENVELOPE = {"label", "owner", "applicationId", "requestId"}


@dataclass(frozen=True)
class _Op:
    """一个操作的固定字段表。

    ★ 为什么要固定：以前是 `args = {k: v for k, v in body.items() if k not in {...}}`，
      未声明的字段被静默丢弃 —— 客户端把 `expires` 拼错成 `expiry`，
      服务端不报错，只是用了别的默认行为。现在多一个字段、少一个字段都是 400。
    """
    args: tuple          # 必需的业务字段
    call: object         # (handler, label, args) → 结果
    mutates: bool        # 是否改状态（决定要不要 requestId 幂等）
    needs_app: bool = True


OPERATIONS: dict[str, _Op] = {
    "set-application": _Op(
        args=("appId",), needs_app=False, mutates=True,
        call=lambda h, lb, a: h.set_application(lb, a["appId"])),
    "accept-rr": _Op(
        args=("rr",), mutates=True,
        call=lambda h, lb, a: h.accept_rr(lb, a["rr"])),
    "accept-g4": _Op(
        args=(), mutates=True,
        call=lambda h, lb, a: h.accept_g4(lb)),
    "build-ar": _Op(
        args=("expires",), mutates=True,
        call=lambda h, lb, a: h.build_ar(lb, expires=a["expires"])),
    "open-cmm": _Op(
        args=("cmm",), mutates=True,
        call=lambda h, lb, a: h.open_cmm(lb, a["cmm"])),
    "build-paci": _Op(
        args=("selection",), mutates=True,
        call=lambda h, lb, a: h.build_paci(lb, selection=a["selection"])),
    "accept-par": _Op(
        args=("par",), mutates=True,
        call=lambda h, lb, a: h.accept_par(lb, a["par"])),
    "build-didgr": _Op(
        args=("expires",), mutates=True,
        call=lambda h, lb, a: h.build_didgr(lb, expires=a["expires"])),
    "verify-final": _Op(
        args=("final", "attestation"), mutates=True,
        call=lambda h, lb, a: h.verify_final(lb, a["final"], a["attestation"])),
    "accept-final": _Op(
        args=(), mutates=True,
        call=lambda h, lb, a: h.accept_final(lb)),
    "publication-receipt": _Op(
        args=(), mutates=False,
        call=lambda h, lb, a: h.publication_receipt(lb)),
    "credential": _Op(
        args=(), mutates=False,
        call=lambda h, lb, a: h.credential(lb)),
    "pending-request": _Op(
        args=(), needs_app=False, mutates=False,
        call=lambda h, lb, a: h.pending_request(lb)),
    "events": _Op(
        args=(), mutates=False,
        call=lambda h, lb, a: {"events": h.events(lb)}),
}


def check_fields(operation: str, spec: _Op, body: dict) -> None:
    """字段表校验：缺字段、多字段、类型不对都是 400。"""
    allowed = {"label", "owner", *spec.args}
    if spec.needs_app:
        allowed.add("applicationId")
    if spec.mutates:
        allowed.add("requestId")
    if operation == "pending-request":
        allowed.add("applicationId")      # 可选：带了就校验，不带也放行

    missing = [f for f in spec.args if f not in body]
    if spec.mutates and not body.get("requestId"):
        missing.append("requestId")
    if missing:
        raise ValueError(f"{operation} 缺少字段：{'、'.join(missing)}")
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise ValueError(f"{operation} 不接受字段：{'、'.join(unknown)}")
    if spec.mutates and not isinstance(body["requestId"], str):
        raise ValueError("requestId 必须是字符串")


def shape(result) -> dict:
    return result if isinstance(result, dict) else {"ok": True}


def _digest(body: dict) -> str:
    """请求指纹（不含 requestId 本身）：判断"同号"是重放还是撞号。"""
    import hashlib

    payload = {k: v for k, v in body.items() if k != "requestId"}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_app(*, ctx: ExecutorContext) -> FastAPI:
    if ctx.profile == "user-controlled" and not getattr(ctx.handler, "user_controlled", False):
        raise RuntimeError("服务端持钥的测试执行器不能声明 user-controlled")
    app = FastAPI(title="user-executor-test", version="1.0.0")
    app.state.profile = ctx.profile
    install_errors(app)

    @app.exception_handler(CredentialHandlerError)
    async def credential_error(_, exc: CredentialHandlerError):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=409, content={"code": 409, "message": str(exc)})

    def authorize(authorization: str | None) -> None:
        expected = f"Bearer {ctx.token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid executor credential")

    def label(body: dict, owner: str) -> str:
        value = body.get("label")
        if not isinstance(value, str) or not value:
            raise ValueError("缺少执行器标签")
        if ctx.handler.owner != owner:
            raise HTTPException(status_code=403, detail="executor owner mismatch")
        return value

    async def read_body(request: Request) -> dict:
        """读 body 并限长。一个执行器只服务一个 owner，没有大请求的正当用途。"""
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="executor request too large")
        try:
            raw = await request.body()
        except Exception as exc:                          # noqa: BLE001
            # Hypercorn/Uvicorn may reset the socket after Content-Length rejection.
            # If the declared size exceeded our cap, normalize that server-level
            # rejection to the executor contract's stable 413 response.
            if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="executor request too large") from exc
            raise
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="executor request too large")
        try:
            body = json.loads(raw or b"{}")
        except ValueError as exc:
            raise ValueError(f"请求体不是合法 JSON：{exc}") from exc
        if not isinstance(body, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return body

    def check_application(operation: str, spec: _Op, body: dict, execution_label: str) -> None:
        """应用绑定由执行器端强制：客户端的内存映射不作权威。"""
        bound = ctx.handler.application_id(execution_label)
        if operation == "set-application":
            if bound is not None and bound != body["appId"]:
                raise HTTPException(status_code=403, detail="executor application mismatch")
            return
        app_id = body.get("applicationId")
        if not spec.needs_app:                     # pending-request：带了就校验
            if app_id is not None and bound != app_id:
                raise HTTPException(status_code=403, detail="executor application mismatch")
            return
        if not isinstance(app_id, str) or not app_id:
            raise HTTPException(status_code=409,
                                detail="executor operation requires applicationId")
        if bound is None:
            raise HTTPException(status_code=409,
                                detail="executor label is not bound to an application")
        if bound != app_id:
            raise HTTPException(status_code=403, detail="executor application mismatch")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "user-executor", "profile": ctx.profile}

    @app.get("/v1/executor/public-key")
    def public_key(authorization: str | None = Header(default=None)):
        authorize(authorization)
        return {"signPk": ctx.handler.public_signing_key(), "owner": ctx.handler.owner,
                "profile": ctx.profile,
                "userControlledExecution": bool(getattr(ctx.handler, "user_controlled", False))}

    @app.post("/v1/executor/login-body")
    def login_body(body: dict = Body(...), authorization: str | None = Header(default=None)):
        authorize(authorization)
        return ctx.handler.login_body(body["challenge"])

    @app.post("/v1/executor/build-cr")
    def build_cr(body: dict = Body(...), authorization: str | None = Header(default=None)):
        authorize(authorization)
        args = dict(body)
        execution_label = args.pop("label")
        if ctx.handler.owner != args.pop("owner"):
            raise HTTPException(status_code=403, detail="executor owner mismatch")
        return {"cr": ctx.handler.build_cr(label=execution_label, **args)}

    @app.get("/v1/executor/{label}/application")
    def application_binding(label: str, authorization: str | None = Header(default=None)):
        authorize(authorization)
        return {"applicationId": ctx.handler.application_id(label)}

    @app.post("/v1/executor/{operation}")
    async def operation(operation: str, request: Request,
                        authorization: str | None = Header(default=None)):
        authorize(authorization)
        if operation not in OPERATIONS:
            raise HTTPException(status_code=404, detail="unsupported executor operation")
        spec = OPERATIONS[operation]
        body = await read_body(request)
        check_fields(operation, spec, body)
        execution_label = label(body, body.get("owner", ""))

        args = {k: v for k, v in body.items() if k not in _ENVELOPE}
        if not spec.mutates:
            check_application(operation, spec, body, execution_label)
            return shape(spec.call(ctx.handler, execution_label, args))

        # 幂等要在业务校验之前：重放必须拿回首次结果，而不是被绑定检查拦掉。
        # ★ 顺序错过一次 —— check_application 放在前面时，同号重放先被 403 拦住，
        #   永远到不了缓存，幂等等于没做。
        rid = body["requestId"]
        fingerprint = _digest(body)
        cached = ctx.handler.replay(execution_label, operation, rid)
        if cached is not None:
            # 同号不同内容是客户端错误，不是重放：返回旧结果会掩盖它。
            if cached.get("fingerprint") != fingerprint:
                raise Conflict(f"requestId {rid} 已用于内容不同的请求")
            return cached["result"]

        check_application(operation, spec, body, execution_label)
        result = shape(spec.call(ctx.handler, execution_label, args))
        ctx.handler.remember(execution_label, operation, rid,
                             {"fingerprint": fingerprint, "result": result})
        return result

    return app


def _from_env():
    import os
    from pathlib import Path

    from user_credential_handler import UserCredentialHandler

    assert_single_worker("executor-service")
    bind = os.environ.get("TPAA_EXECUTOR_BIND", "127.0.0.1").strip()
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError("test executor must bind to loopback only")
    handler = UserCredentialHandler(Path(env_required("TPAA_EXECUTOR_STATE_ROOT")))
    return create_app(ctx=ExecutorContext(handler=handler, token=env_required("TPAA_EXECUTOR_TOKEN")))


app = LazyApp(_from_env)

__all__ = ["ExecutorContext", "create_app", "app"]
