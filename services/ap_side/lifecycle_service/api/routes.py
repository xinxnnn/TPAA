"""lifecycle-service 的端点与错误映射。

★ 吊销端点返回 200 且带 `notLocal` 明细，而不是"全部成功"。
  把"广播里有、本机没有"这件事显式说出来，是为了让调用方看得见数字对不上 ——
  一个永远返回 200 {} 的接口，会让人以为全网都停干净了。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from localstore import GuardViolation, StoreLayoutError

from ..domain.entities import LifecycleError, RevocationNotice
from ..domain.usecases.recover import RecoverCommand, RecoverUseCase
from ..domain.usecases.revocation import HandleRevocationUseCase
from .schemas import ErrorOut, RecoverIn, RecoverOut, RevocationIn, RevocationOut

log = logging.getLogger("lifecycle-service")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(LifecycleError)
        async def _life(_: Request, exc: LifecycleError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(GuardViolation)
        async def _guard(_: Request, exc: GuardViolation):
            # 找回时撞上 CMI 不一致 —— 已冻结，不自动修复
            return JSONResponse(
                status_code=409,
                content=ErrorOut(
                    code=int(ErrorCode.CONFLICT),
                    message="实例已被冻结：模块内容与本地承诺不一致",
                    detail=str(exc)).model_dump())

        @app.exception_handler(StoreLayoutError)
        async def _layout(_: Request, exc: StoreLayoutError):
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
    revoke_uc = HandleRevocationUseCase(ctx)
    recover_uc = RecoverUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "lifecycle-service", "domain": "ap-side",
                "problems": errs}

    @app.post("/v1/revocations", response_model=RevocationOut)
    def receive_revocation(body: RevocationIn):
        out = revoke_uc.execute(RevocationNotice(
            root_did=body.rootDid, revoked=body.revoked,
            case_ref=body.caseRef, reason=body.reason))
        log.warning("承接吊销：root=%s stopped=%d notLocal=%d",
                    out.root_did, len(out.stopped), len(out.not_local))
        return RevocationOut(rootDid=out.root_did, stopped=out.stopped,
                             already=out.already, notLocal=out.not_local,
                             caseRef=out.case_ref)

    @app.post("/v1/agents/{did:path}/recover", response_model=RecoverOut)
    def recover(did: str, body: RecoverIn):
        out = recover_uc.execute(RecoverCommand(
            did=did, identity_hash=int(body.identityHash, 16)))
        return RecoverOut(did=out.did, rebuilt=out.rebuilt, cmi=out.cmi,
                          buildDigest=out.build_digest,
                          buildDigestChanged=out.build_digest_changed,
                          note=out.note)


__all__ = ["install_routes", "_HttpMapping"]
