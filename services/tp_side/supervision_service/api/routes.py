"""supervision-service 的端点与错误映射。

状态码的分工在这里尤其要紧：

    403  `NotFiled` —— **未立案**。语义是"你在越权"，不是"你填错了"。
         它会进安全日志被单独统计：有人试图在没立案的情况下还原身份。
    409  状态迁移非法 / 重复立案 / 同一人签两次 —— 流程冲突
    400  参数错

把 403 和 400 合并，等于把"越权尝试"降级成"手滑"，那就没人会去看它。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from services.shared.store import StoreError

from ..domain.entities import CaseError, IllegalCaseTransition, NotFiled
from ..domain.usecases.disclose import DiscloseUseCase
from ..domain.usecases.file_case import (
    FileCaseUseCase,
    FileCommand,
    RejectCaseUseCase,
)
from ..domain.usecases.forensics import ForensicsUseCase
from ..domain.usecases.investigate import CollectProofUseCase, InvestigateUseCase
from ..domain.usecases.report_case import ReportCaseUseCase, ReportCommand
from .schemas import (
    CaseOut,
    CollectIn,
    DiscloseOut,
    ErrorOut,
    FileIn,
    FileOut,
    ForensicIn,
    ForensicOut,
    InvestigateIn,
    InvestigateOut,
    RejectIn,
    ReportIn,
    ReportOut,
)

log = logging.getLogger("supervision-service")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(NotFiled)
        async def _notfiled(_: Request, exc: NotFiled):
            log.warning("越权追溯尝试被拒：%s", exc)
            return JSONResponse(
                status_code=403,
                content=ErrorOut(code=int(ErrorCode.FORBIDDEN),
                                 message="案件未立案，禁止追溯动作",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(IllegalCaseTransition)
        async def _illegal(_: Request, exc: IllegalCaseTransition):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message="案件状态不允许该动作",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(CaseError)
        async def _case(_: Request, exc: CaseError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(StoreError)
        async def _store(_: Request, exc: StoreError):
            log.error("案件库故障：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="案件库暂不可用",
                                 detail=str(exc)).model_dump())

        @app.exception_handler(ValueError)
        async def _bad(_: Request, exc: ValueError):
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
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
    report_uc = ReportCaseUseCase(ctx)
    file_uc = FileCaseUseCase(ctx)
    reject_uc = RejectCaseUseCase(ctx)
    invest_uc = InvestigateUseCase(ctx)
    collect_uc = CollectProofUseCase(ctx)
    disclose_uc = DiscloseUseCase(ctx)
    forensic_uc = ForensicsUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        warns = ctx.warnings() if hasattr(ctx, "warnings") else []
        return {"status": "ok" if not errs and not warns
                else ("degraded" if not errs else "error"),
                "service": "supervision-service", "domain": "tp-side",
                "problems": errs + warns}

    # ---- 受理 ----
    @app.post("/v1/cases", response_model=ReportOut)
    def report(body: ReportIn):
        out = report_uc.execute(ReportCommand(
            subject_did=body.subjectDid, reporter=body.reporter,
            allegation=body.allegation, evidence_ref=body.evidenceRef))
        return ReportOut(caseId=out.case_id, subjectDid=out.subject_did,
                         state=out.state, reportedAt=out.reported_at)

    @app.get("/v1/cases/{case_id}", response_model=CaseOut)
    def get_case(case_id: str):
        case = ctx.cases.get(case_id)
        if case is None:
            raise ValueError(f"案件 {case_id} 不存在")
        return CaseOut(**case.to_json())

    # ---- 立案 ----
    @app.post("/v1/cases/{case_id}/file", response_model=FileOut)
    def file_case(case_id: str, body: FileIn):
        out = file_uc.execute(FileCommand(case_id=case_id,
                                          reviewers=body.reviewers,
                                          note=body.note))
        return FileOut(caseId=out.case_id, subjectDid=out.subject_did,
                       state=out.state, filedAt=out.filed_at,
                       reviewers=out.reviewers)

    @app.post("/v1/cases/{case_id}/reject", response_model=FileOut)
    def reject(case_id: str, body: RejectIn):
        out = reject_uc.execute(case_id=case_id, reviewer=body.reviewer,
                                note=body.note)
        return FileOut(caseId=out.case_id, subjectDid=out.subject_did,
                       state=out.state)

    # ---- 协查 ----
    @app.post("/v1/cases/{case_id}/investigate", response_model=InvestigateOut)
    def investigate(case_id: str, body: InvestigateIn):
        out = invest_uc.execute(case_id=case_id, requested_by=body.requestedBy)
        return InvestigateOut(caseId=out.case_id, ticketId=out.ticket_id,
                              state=out.state, lineageChain=out.lineage_chain)

    @app.post("/v1/cases/{case_id}/collect", response_model=CaseOut)
    def collect(case_id: str, body: CollectIn):
        collect_uc.execute(case_id=case_id, ticket_id=body.ticketId)
        case = ctx.cases.get(case_id)
        return CaseOut(**case.to_json())

    # ---- 揭露 ----
    @app.post("/v1/cases/{case_id}/disclose", response_model=DiscloseOut)
    def disclose(case_id: str):
        out = disclose_uc.execute(case_id=case_id, requested_by="supervision")
        return DiscloseOut(caseId=out.case_id, subjectDid=out.subject_did,
                           identityHash=out.identity_hash,
                           identityDigest=out.identity_digest,
                           state=out.state, verified=out.verified,
                           verifyNote=out.verify_note)

    # ---- 取证 ----
    @app.post("/v1/cases/{case_id}/forensics", response_model=ForensicOut)
    def forensics(case_id: str, body: ForensicIn):
        out = forensic_uc.execute(case_id=case_id, exported_by=body.exportedBy)
        return ForensicOut(caseId=out.case_id, subjectDid=out.subject_did,
                           state=out.state, envelopeDigest=out.envelope_digest,
                           envelopeBytes=out.envelope_bytes,
                           chainVerified=out.chain_verified,
                           verdictReason=out.verdict_reason,
                           sealedAt=out.sealed_at, timeline=out.timeline)


__all__ = ["install_routes", "_HttpMapping"]
