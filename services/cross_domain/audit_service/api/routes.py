"""audit-service 的端点与错误映射。

★ 这里**没有** update / delete 端点，也没有"修复链"的端点。
  链断了就报断在第几条，让人去查；自动修复只会把证据变成猜测。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from services.shared.store import StoreError

from ..domain.usecases.export import ExportCaseUseCase, VerifyChainUseCase
from ..domain.usecases.record import AttestPhcUseCase, RecordUseCase
from .schemas import (
    AttestIn,
    BundleOut,
    EntryOut,
    ErrorOut,
    ExportIn,
    RecordIn,
    RecordOut,
    VerifyOut,
)

log = logging.getLogger("audit-service")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(StoreError)
        async def _store(_: Request, exc: StoreError):
            log.error("审计账本故障：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="审计账本暂不可用",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(TPAAError)
        async def _tpaa(_: Request, exc: TPAAError):
            status = {ErrorCode.NOT_FOUND: 404, ErrorCode.INTERNAL: 500}.get(exc.code, 400)
            return JSONResponse(status_code=status, content=exc.to_response())

        # ★ 没有这个 handler，"导出时不写案由"会变成一个 500 ——
        #   操作者会以为服务坏了，去翻日志，而真正的问题是请求本身不成立。
        #   校验类错误必须落在 4xx，否则 5xx 就不再意味着"我们出问题了"。
        @app.exception_handler(ValueError)
        async def _bad(_: Request, exc: ValueError):
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
                                 message=str(exc)).model_dump())

        @app.exception_handler(Exception)
        async def _boom(_: Request, exc: Exception):
            log.exception("未处理异常")
            return JSONResponse(
                status_code=500,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="内部错误").model_dump())


def install_routes(app: FastAPI, ctx) -> None:
    record_uc = RecordUseCase(ctx)
    attest_uc = AttestPhcUseCase(ctx)
    verify_uc = VerifyChainUseCase(ctx)
    export_uc = ExportCaseUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        warns = ctx.warnings()
        return {"status": "ok" if not errs and not warns
                else ("degraded" if not errs else "error"),
                "service": "audit-service", "domain": "cross-domain",
                "entries": len(ctx.ledger.all()),
                "problems": errs + warns}

    @app.post("/v1/audit/entries", response_model=RecordOut)
    def record(body: RecordIn):
        out = record_uc.execute(kind=body.kind, subject=body.subject,
                                payload=body.payload)
        return RecordOut(entryId=out.entry_id, seq=out.seq, hash=out.hash)

    @app.post("/v1/audit/attest", response_model=RecordOut)
    def attest(body: AttestIn):
        out = attest_uc.execute(did=body.did, phc_json=body.phc,
                                parent_did=body.parentDid)
        return RecordOut(entryId=out.entry_id, seq=out.seq, hash=out.hash)

    @app.get("/v1/audit/verify", response_model=VerifyOut)
    def verify():
        v = verify_uc.execute()
        return VerifyOut(ok=v.ok, length=v.length, brokenAt=v.broken_at,
                         reason=v.reason)

    @app.get("/v1/audit/entries", response_model=list[EntryOut])
    def list_entries(kind: str = "", subject: str = ""):
        items = ctx.ledger.all()
        if kind:
            items = [e for e in items if e.kind == kind]
        if subject:
            items = [e for e in items if e.subject == subject]
        return [EntryOut(**e.to_json()) for e in items]

    @app.post("/v1/audit/export", response_model=BundleOut)
    def export(body: ExportIn):
        b = export_uc.execute(case_ref=body.caseRef, subjects=body.subjects,
                              include_all=body.includeAll)
        return BundleOut(**b.to_json())


__all__ = ["install_routes", "_HttpMapping"]
