"""gateway 的端点与错误映射。

★ 状态码分工：

    403  出口卡口拦下 —— 这是**安全事件**，不是业务拒绝
    400  收到的东西本身不成立（缺案由、缺字段）
    409  状态冲突（重复答复、类别不支持）
    503  对岸不可达 —— 调用方该重试，不该改参数

    把 403 单独拎出来的理由与 coordination 那头一致：
    它要单独进安全日志被统计。一个每月被拦一次的卡口，
    和一个月被拦三千次的卡口，是两种不同的事故。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError

from ..domain.entities import (BadNotice, ChannelDown, ExportBlocked,
                               GatewayError)
from ..domain.usecases.intake import IntakeRevocationUseCase, RevocationCommand
from ..domain.usecases.outbox import DrainOutboxUseCase
from .schemas import (DrainIn, DrainOut, ErrorOut, ItemOut, RevocationIn,
                      RevocationOut)

log = logging.getLogger("gateway")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(ExportBlocked)
        async def _blocked(_: Request, exc: ExportBlocked):
            # ★ 安全事件：单独告警，不与普通拒绝混在一起
            log.error("出口卡口拦截：%s", exc)
            return JSONResponse(
                status_code=403,
                content=ErrorOut(code=int(ErrorCode.FORBIDDEN),
                                 message="答复含未登记字段，已阻止出网",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(BadNotice)
        async def _bad(_: Request, exc: BadNotice):
            log.warning("拒绝承接：%s", exc)
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
                                 message=str(exc)).model_dump())

        @app.exception_handler(ChannelDown)
        async def _down(_: Request, exc: ChannelDown):
            # 对岸不可用 —— 调用方该等一会儿再来，不是改参数
            log.warning("跨域通道不可用：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=503, message=str(exc)).model_dump())

        @app.exception_handler(GatewayError)
        async def _gw(_: Request, exc: GatewayError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

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
    drain_uc = DrainOutboxUseCase(ctx)
    intake_uc = IntakeRevocationUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "gateway", "domain": "ap-side",
                "selfId": ctx.self_id,
                "allowedKinds": list(ctx.allowed_kinds),
                "problems": errs}

    @app.post("/v1/outbox/drain", response_model=DrainOut)
    def drain(body: DrainIn | None = None):
        """处理收件箱：拉一批待答工单，逐张应答并回写。"""
        limit = (body.limit if body else 0) or 0
        rep = drain_uc.execute(limit=limit or None)
        if rep.blocked:
            log.error("本次处理有 %d 张被出口卡口拦下：%s",
                      len(rep.blocked), rep.blocked)
        return DrainOut(polled=rep.polled, answered=rep.answered,
                        blocked=list(rep.blocked),
                        items=[ItemOut(**i.to_json()) for i in rep.items])

    @app.get("/v1/outbox/pending")
    def pending(limit: int = 100):
        """只看不处理 —— 给运���看积压。★ 不产生任何写副作用。"""
        got = ctx.channel.pull(responder=ctx.self_id, state="pending",
                               limit=limit)
        return {"responder": ctx.self_id, "count": len(got),
                "tickets": [t.ticket_id for t in got]}

    @app.post("/v1/revocations", response_model=RevocationOut)
    def receive_revocation(body: RevocationIn):
        out = intake_uc.execute(RevocationCommand(
            root_did=body.rootDid, revoked=list(body.revoked),
            case_ref=body.caseRef, reason=body.reason))
        log.warning("承接吊销：root=%s stopped=%d notLocal=%d case=%s",
                    out.root_did, len(out.stopped), len(out.not_local),
                    out.case_ref)
        return RevocationOut(**out.to_json())


__all__ = ["install_routes", "_HttpMapping"]
