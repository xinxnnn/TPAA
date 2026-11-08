"""policy-service 的端点与错误映射。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from services.shared.store import StoreError

from ..domain.entities import MissingGrounds, PolicyError
from ..domain.usecases.revoke import ResendNoticeUseCase, RevokeCommand, RevokeUseCase
from .schemas import ErrorOut, OrderOut, RevokeIn, RevokeOut

log = logging.getLogger("policy-service")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(MissingGrounds)
        async def _grounds(_: Request, exc: MissingGrounds):
            # 缺案由不是"手滑"，是这条令本身站不住 —— 给它 403 而不是 400，
            # 这样它会进安全日志，而不是混在一堆格式错误里。
            return JSONResponse(
                status_code=403,
                content=ErrorOut(code=int(ErrorCode.FORBIDDEN),
                                 message="吊销令缺少必要依据",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(PolicyError)
        async def _policy(_: Request, exc: PolicyError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(StoreError)
        async def _store(_: Request, exc: StoreError):
            log.error("吊销令库故障：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="吊销令库暂不可用",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(TPAAError)
        async def _tpaa(_: Request, exc: TPAAError):
            status = {ErrorCode.NOT_FOUND: 404, ErrorCode.CONFLICT: 409,
                      ErrorCode.FORBIDDEN: 403,
                      ErrorCode.INTERNAL: 500}.get(exc.code, 400)
            return JSONResponse(status_code=status, content=exc.to_response())

        @app.exception_handler(Exception)
        async def _boom(_: Request, exc: Exception):
            log.exception("未处理异常")
            return JSONResponse(
                status_code=500,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="内部错误").model_dump())


def install_routes(app: FastAPI, ctx) -> None:
    revoke_uc = RevokeUseCase(ctx)
    resend_uc = ResendNoticeUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "policy-service", "domain": "cross-domain",
                "orders": len(ctx.orders.all()), "problems": errs}

    @app.post("/v1/revocations", response_model=RevokeOut)
    def revoke(body: RevokeIn):
        out = revoke_uc.execute(RevokeCommand(
            root_did=body.rootDid, case_ref=body.caseRef,
            reason=body.reason, issued_by=body.issuedBy))
        return RevokeOut(orderId=out.order_id, state=out.state,
                         revoked=out.revoked, alreadyRevoked=out.already_revoked,
                         notified=out.notified, failure=out.failure)

    @app.post("/v1/revocations/{order_id}/resend", response_model=RevokeOut)
    def resend(order_id: str):
        out = resend_uc.execute(order_id=order_id)
        return RevokeOut(orderId=out.order_id, state=out.state,
                         revoked=out.revoked, alreadyRevoked=out.already_revoked,
                         notified=out.notified)

    @app.get("/v1/revocations/{order_id}", response_model=OrderOut)
    def get_order(order_id: str):
        order = ctx.orders.get(order_id)
        if order is None:
            raise ValueError(f"吊销令 {order_id} 不存在")
        return OrderOut(**order.to_json())


__all__ = ["install_routes", "_HttpMapping"]
