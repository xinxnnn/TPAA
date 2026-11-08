"""coordination 的端点与错误映射。

这里的状态码分工值得单独说一句：

    403  载荷里带了不该跨域的东西 —— 这是**红线问题**，不是格式问题
    429  限流 —— 调用方该等，而不是改参数
    409  重复答复 —— 状态冲突
    404  工单不存在

把 403 与 400 分开的意义：403 意味着"你在试图让通道运一个不该运的东西"，
这种请求会进安全日志被单独统计；400 只是手滑。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from services.shared.store import StoreError

from ..domain.entities import ChannelError, NonPublicPayload, RateLimited
from ..domain.usecases.answer_ticket import (
    AnswerTicketUseCase,
    GetTicketUseCase,
    TicketNotFound,
)
from ..domain.usecases.list_tickets import ListCommand, ListError, ListTicketsUseCase
from ..domain.usecases.open_ticket import OpenTicketUseCase
from .schemas import (AnswerIn, AnswerOut, ErrorOut, ListOut, OpenIn, OpenOut,
                      TicketOut)

log = logging.getLogger("coordination")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(NonPublicPayload)
        async def _nonpublic(_: Request, exc: NonPublicPayload):
            log.warning("跨域卡口拦截：%s", exc)
            return JSONResponse(
                status_code=403,
                content=ErrorOut(code=int(ErrorCode.FORBIDDEN),
                                 message="载荷含不得跨域传递的内容",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(RateLimited)
        async def _limited(_: Request, exc: RateLimited):
            return JSONResponse(
                status_code=429,
                content=ErrorOut(code=429, message="协查配额已满",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(TicketNotFound)
        async def _nf(_: Request, exc: TicketNotFound):
            return JSONResponse(
                status_code=404,
                content=ErrorOut(code=int(ErrorCode.NOT_FOUND),
                                 message=str(exc)).model_dump())

        @app.exception_handler(ChannelError)
        async def _chan(_: Request, exc: ChannelError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(ListError)
        async def _list(_: Request, exc: ListError):
            # 没带 responder 就来列收件箱 —— 默认拒绝，不返回全部
            log.warning("收件箱查询被拒：%s", exc)
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
                                 message=str(exc)).model_dump())

        @app.exception_handler(StoreError)
        async def _store(_: Request, exc: StoreError):
            # 库坏了是运维故障，不能给 4xx 让人以为是自己填错
            log.error("工单库故障：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="跨域通道暂不可用（工单库故障）",
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
    open_uc = OpenTicketUseCase(ctx)
    answer_uc = AnswerTicketUseCase(ctx)
    get_uc = GetTicketUseCase(ctx)
    list_uc = ListTicketsUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "coordination", "domain": "cross-domain",
                "tickets": len(ctx.tickets.all()), "problems": errs}

    @app.post("/v1/tickets", response_model=OpenOut)
    def open_ticket(body: OpenIn):
        t = open_uc.execute(requester=body.requester, responder=body.responder,
                            kind=body.kind, payload=body.payload,
                            case_ref=body.caseRef, ttl_hours=body.ttlHours)
        return OpenOut(ticketId=t.ticket_id, requester=t.requester,
                       responder=t.responder, kind=t.kind,
                       state=t.state.value, createdAt=t.created_at,
                       caseRef=t.case_ref)

    @app.get("/v1/tickets", response_model=ListOut)
    def list_tickets(responder: str = Query(default="", description="必填：TP 或 AP"),
                     state: str = Query(default="pending"),
                     caseRef: str = Query(default=""),
                     limit: int = Query(default=100, ge=1, le=500)):
        """收件箱：列出**发给 responder 自己**的待答工单。

        ★ responder 必填且不接受空值 —— 不带过滤的查询一律拒绝，
          而不是退化成"返回全部"。跨域询问的分布本身就是敏感信息。
        """
        got = list_uc.execute(ListCommand(responder=responder, state=state,
                                          case_ref=caseRef, limit=limit))
        return ListOut(responder=responder.strip().upper(), state=state,
                       count=len(got),
                       tickets=[TicketOut(**t.to_json()) for t in got])

    @app.get("/v1/tickets/{ticket_id}", response_model=TicketOut)
    def get_ticket(ticket_id: str):
        return TicketOut(**get_uc.execute(ticket_id).to_json())

    @app.post("/v1/tickets/{ticket_id}/answer", response_model=AnswerOut)
    def answer(ticket_id: str, body: AnswerIn):
        out = answer_uc.execute(ticket_id=ticket_id, responder=body.responder,
                                answer=body.answer)
        return AnswerOut(ticketId=out.ticket_id, state=out.state,
                         answeredAt=out.answered_at)


__all__ = ["install_routes", "_HttpMapping"]
