"""did-service 的端点与错误映射。

错误语义的三档区分，刻意不合并成 400：

    404  这个号不存在 —— 调用方没做错，是号不存在
    409  重复登记 / 父体不合法 —— 这次请求本身的逻辑站不住
    400  参数格式错

追溯时"查不到"和"这个链不合法"会被分别处理：前者去查是不是填错了号，
后者说明有人在伪造关系。合并成一个 400，排查的人就得自己猜是哪种。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError

from ..domain.entities import (
    DuplicateDid,
    RegistryError,
    UnknownDid,
)
from ..domain.usecases.lookup import (
    ChildrenOfUseCase,
    ResolveDidUseCase,
    TraceLineageUseCase,
)
from ..domain.usecases.register_did import RegisterCommand, RegisterDidUseCase
from ..domain.usecases.reveal import RevealCommand, RevealCscidUseCase
from ..domain.usecases.revoke import RevokeCommand, RevokeDidUseCase
from .schemas import (
    ChildrenOut,
    DidOut,
    ErrorOut,
    RegisterIn,
    RegisterOut,
    RevealIn,
    RevealOut,
    RevokeIn,
    RevokeOut,
    TraceOut,
)

log = logging.getLogger("did-service")


class _HttpMapping:
    def install(self, app: FastAPI) -> None:
        @app.exception_handler(UnknownDid)
        async def _unknown(_: Request, exc: UnknownDid):
            return JSONResponse(
                status_code=404,
                content=ErrorOut(code=int(ErrorCode.NOT_FOUND),
                                 message=str(exc)).model_dump())

        @app.exception_handler(DuplicateDid)
        async def _dup(_: Request, exc: DuplicateDid):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(RegistryError)
        async def _reg(_: Request, exc: RegistryError):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump())

        @app.exception_handler(TPAAError)
        async def _tpaa(_: Request, exc: TPAAError):
            status = {ErrorCode.NOT_FOUND: 404, ErrorCode.CONFLICT: 409,
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
    register_uc = RegisterDidUseCase(ctx)
    resolve_uc = ResolveDidUseCase(ctx)
    trace_uc = TraceLineageUseCase(ctx)
    children_uc = ChildrenOfUseCase(ctx)
    revoke_uc = RevokeDidUseCase(ctx)
    reveal_uc = RevealCscidUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "did-service", "domain": "tp-side",
                "records": ctx.registry.count(), "problems": errs}

    @app.post("/v1/dids/register", response_model=RegisterOut)
    def register(body: RegisterIn):
        out = register_uc.execute(RegisterCommand(
            did=body.did,
            identity_hash=int(body.identityHash, 16),
            parent_did=body.parentDid,
            ecid_ref=body.ecidRef,
            confirmed_by_user=body.confirmedByUser,
            confirm_evidence=body.confirmEvidence,
        ))
        return RegisterOut(did=out.did, parentDid=out.parent_did,
                           agentType=out.agent_type, registeredAt=out.registered_at,
                           cscidSealed=out.cscid_sealed)

    # ★ 顺序要紧：`{did:path}` 会吞掉斜杠，
    #   所以 /trace 与 /children 必须排在它前面，否则 GET /v1/dids/abc/trace
    #   会被解析成 did="abc/trace" —— 报 404 而不是上溯，且极难排查。
    @app.get("/v1/dids/{did:path}/trace", response_model=TraceOut)
    def trace(did: str):
        lin = trace_uc.execute(did)
        return TraceOut(did=did, chain=lin.chain, root=lin.root, depth=lin.depth)

    @app.get("/v1/dids/{did:path}/children", response_model=ChildrenOut)
    def children(did: str):
        return ChildrenOut(did=did, children=children_uc.execute(did))

    @app.get("/v1/dids/{did:path}", response_model=DidOut)
    def resolve(did: str):
        rec = resolve_uc.execute(did)
        return DidOut(**rec.to_json())

    @app.post("/v1/dids/{did:path}/cscid", response_model=RevealOut)
    def reveal_cscid(did: str, body: RevealIn):
        """受控揭示：把封存的 CSCID（密文）交给监管。

        ★ 本端点**不校验立案状态**（号码簿不认识案由），只留痕。
          真正的闸门在 supervision-service 的用例里；
          「只有 TP 区内网能调」由 mTLS 与网络策略保证。
          取走的是密文，打不开 —— 打开它的密钥从不进入本服务。
        """
        out = reveal_uc.execute(RevealCommand(
            did=did, case_ref=body.caseRef, requested_by=body.requestedBy))
        return RevealOut(did=out.did, cscid=out.cscid, caseRef=out.case_ref)

    @app.post("/v1/dids/revoke", response_model=RevokeOut)
    def revoke(body: RevokeIn):
        out = revoke_uc.execute(RevokeCommand(did=body.did, reason=body.reason,
                                              by=body.by))
        return RevokeOut(root=out.root, revoked=out.revoked,
                         alreadyRevoked=out.already_revoked)


__all__ = ["install_routes", "_HttpMapping"]
