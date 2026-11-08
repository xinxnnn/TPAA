"""HTTP 层：把用例接上端点，并把"拒绝"翻译成有语义的 HTTP 状态。

三条原则：

1. **错误码不是 HTTP 码的复读机。**
   1401（未经确认）与 400（参数错）都可能是 4xx，但前者是权限问题、
   后者是格式问题。前端要据此决定"重弹确认框"还是"提示填错"。

2. **不把内部异常原样吐给外面。**
   `CapabilityError` 里可能带 TP 的细节；对外统一成"上游拒绝"，
   细节进日志。但 401/403 这类"你自己做错了"的错误要原样说清楚 ——
   那正是用户需要知道的部分。

3. **闸门的拒绝必须可区分。**
   "没确认"和"确认过了但方案被改"是两种完全不同的体验：
   前者要引导确认，后者要提示"你改过方案，请重新确认"。
   把它们合并成一个 400，等于让用户自己去猜。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.shared.dto import ErrorCode
from services.shared.errors import TPAAError
from localstore import GuardViolation, IndexCorrupted, StoreLayoutError

from ..domain.entities import IllegalTransition, NotConfirmed
from ..domain.services.context import ConfigError
from ..domain.usecases.derive_subagent import (
    ConfirmationTicket,
    DeriveSubAgentUseCase,
)
from ..domain.usecases.issue_agent import (
    IssueAgentUseCase,
    IssueCommand,
    IssueRejected,
)
from ..domain.usecases.recover_agent import (
    RecoverAgentUseCase,
    RecoverRejected,
)
from ..domain.entities import ConfirmToken, ModuleChoice, Selection
from .schemas import (
    ConfirmIn,
    ConfirmOut,
    DeriveIn,
    DeriveOut,
    ErrorOut,
    IssueIn,
    IssueOut,
    LocateOut,
    PrepareIn,
    PrepareOut,
    RecoverIn,
    RecoverOut,
)

log = logging.getLogger("agent-service")


def _selection(items) -> Selection:
    return Selection(choices=tuple(
        ModuleChoice(module_id=i.moduleId, version=i.version) for i in items))


# ---------------------------------------------------------------------------
# 异常 → HTTP
# ---------------------------------------------------------------------------


class _HttpMapping:
    """一张显式的对照表。放在一处，是为了让"哪些拒绝会被看到"可审计。"""

    def __init__(self) -> None:
        self.app: FastAPI | None = None

    def install(self, app: FastAPI) -> None:
        self.app = app

        @app.exception_handler(NotConfirmed)
        async def _not_confirmed(_: Request, exc: NotConfirmed):
            # 1401：语义是"这件事需要用户点头，而现在没有"
            return JSONResponse(
                status_code=403,
                content=ErrorOut(code=int(ErrorCode.NOT_CONFIRMED),
                                 message=str(exc)).model_dump(),
            )

        @app.exception_handler(IllegalTransition)
        async def _illegal(_: Request, exc: IllegalTransition):
            return JSONResponse(
                status_code=409,
                content=ErrorOut(code=int(ErrorCode.CONFLICT),
                                 message=str(exc)).model_dump(),
            )

        @app.exception_handler(GuardViolation)
        async def _guard(_: Request, exc: GuardViolation):
            # ★ CMI 不一致 = 冻结 + 拒绝，且**不自动修复**。
            #   这里必须让调用方看到"被冻结"这个事实，而不是一个笼统的 500。
            return JSONResponse(
                status_code=409,
                content=ErrorOut(
                    code=int(ErrorCode.CONFLICT),
                    message="实例已被冻结：模块内容与本地承诺不一致",
                    detail=(f"did={exc.did} expected={exc.expected[:16]}… "
                            f"actual={exc.actual[:16]}…；需人工复核后再解冻"),
                ).model_dump(),
            )

        @app.exception_handler(IssueRejected)
        @app.exception_handler(RecoverRejected)
        async def _rejected(_: Request, exc: Exception):
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
                                 message=str(exc)).model_dump(),
            )

        @app.exception_handler(IndexCorrupted)
        async def _index(_: Request, exc: IndexCorrupted):
            # 索引坏了是**运维级**故障：不能给 4xx，否则会被当成用户输错。
            log.error("身份索引不可解封：%s", exc)
            return JSONResponse(
                status_code=503,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="身份索引暂不可用（密钥不匹配或索引损坏）",
                                 detail=str(exc)).model_dump(),
            )

        @app.exception_handler(StoreLayoutError)
        async def _layout(_: Request, exc: StoreLayoutError):
            return JSONResponse(
                status_code=400,
                content=ErrorOut(code=int(ErrorCode.BAD_REQUEST),
                                 message=str(exc)).model_dump(),
            )

        @app.exception_handler(TPAAError)
        async def _tpaa(_: Request, exc: TPAAError):
            status = 400
            if exc.code in (ErrorCode.UNAUTHORIZED, ErrorCode.NOT_CONFIRMED):
                status = 403
            elif exc.code == ErrorCode.NOT_FOUND:
                status = 404
            elif exc.code == ErrorCode.CONFLICT:
                status = 409
            elif exc.code == ErrorCode.INTERNAL:
                status = 500
            return JSONResponse(status_code=status, content=exc.to_response())

        @app.exception_handler(Exception)
        async def _boom(_: Request, exc: Exception):
            log.exception("未处理异常")
            return JSONResponse(
                status_code=500,
                content=ErrorOut(code=int(ErrorCode.INTERNAL),
                                 message="内部错误").model_dump(),
            )


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------


def install_routes(app: FastAPI, ctx) -> None:
    """把用例挂到 app 上。ctx 由装配层给，路由层不认识任何具体实现。"""

    issue_uc = IssueAgentUseCase(ctx)
    derive_uc = DeriveSubAgentUseCase(ctx)
    recover_uc = RecoverAgentUseCase(ctx)

    @app.get("/healthz")
    def healthz():
        errs = ctx.preflight()
        return {"status": "ok" if not errs else "degraded",
                "service": "agent-service", "domain": "ap-side",
                "problems": errs}

    # ---- 申领 ----
    @app.post("/v1/agents/issue", response_model=IssueOut)
    def issue(body: IssueIn):
        out = issue_uc.execute(IssueCommand(
            identity_hash=int(body.identityHash, 16),
            tau=int(ctx.policy.get("tau", 1)),
            crf=int(ctx.policy.get("crf", 1)),
            selection=_selection(body.selection.items),
            ttl_days=body.ttlDays,
        ))
        return IssueOut(
            did=out.did, cmi=out.cmi, buildDigest=out.build_digest,
            layers=out.layers, keptExisting=out.kept_existing, phc=out.phc_json,
        )

    # ---- 派生：三步 ----
    @app.post("/v1/subagents/prepare", response_model=PrepareOut)
    def prepare(body: PrepareIn):
        t = derive_uc.prepare(
            parent_did=body.parentDid,
            selection=_selection(body.selection.items),
            ttl_hours=body.ttlHours,
        )
        return PrepareOut(
            ticketId=t.ticket_id, parentDid=t.parent_did,
            selectionDigest=t.selection_digest, ttlHours=t.ttl_hours,
            createdAt=t.created_at,
            summary=_summarise(body.selection.items, body.ttlHours),
        )

    @app.post("/v1/subagents/confirm", response_model=ConfirmOut)
    def confirm(body: ConfirmIn):
        sel = _selection(body.selection.items)
        actual = _digest(sel)

        # ★ 比对用户确认的那份摘要。
        #   如果只信调用方传进来的 digest，confirm 就变成了"自己给自己发令牌"；
        #   如果只自己重算，又无法发现"确认界面显示的是 A、请求里带的是 B"。
        #   两边都比，才能保证"用户点头的那份方案"就是"即将执行的那份方案"。
        if body.selectionDigest.strip().lower() != actual:
            raise NotConfirmed(
                "方案摘要与确认内容不一致 —— 确认后方案被改动过，请重新发起确认")

        ticket = ConfirmationTicket(
            ticket_id=body.ticketId,
            parent_did=body.parentDid,
            selection_digest=actual,
            ttl_hours=body.ttlHours,
            created_at=ctx.clock.now(),
        )
        # ★ 确认这一步**只发令牌、不派生**：派生必须由用户拿着令牌再发起一次。
        #   这不是多此一举 —— 它让"确认"与"执行"成为两次独立请求，
        #   所以任何一方都做不到"点一下顺便就把事办了"。
        tok = derive_uc.confirm(token=f"cfm-{ticket.ticket_id}-{_nonce()}", ticket=ticket)
        return ConfirmOut(token=tok.token, selectionDigest=tok.selection_digest,
                          confirmedAt=tok.confirmed_at)

    @app.post("/v1/subagents/derive", response_model=DeriveOut)
    def derive(body: DeriveIn):
        sel = _selection(body.selection.items)
        token = None
        if body.confirmToken:
            loaded = derive_uc.load_ticket(body.confirmToken)
            if loaded is None:
                raise NotConfirmed("确认令牌不存在（未经确认，或已被撤销）")
            token = loaded
        # token 为 None 时**不偷偷补一张**：让 ChildRequest.guard 明确拒掉，
        # 拒绝原因会原样返回给调用方。
        from ..domain.entities import ChildRequest  # 局部导入避免顶部堆叠

        out = derive_uc.execute(ChildRequest(
            parent_did=body.parentDid, selection=sel,
            ttl_hours=body.ttlHours, confirmation=token,
        ))
        return DeriveOut(
            did=out.did, parentDid=out.parent_did, cmi=out.cmi,
            expiresAt=out.expires_at, buildDigest=out.build_digest, phc=out.phc_json,
        )

    # ---- 找回 ----
    @app.get("/v1/agents/locate", response_model=LocateOut)
    def locate(identityHash: str):
        return LocateOut(items=recover_uc.locate(_hid(identityHash)))

    @app.post("/v1/agents/recover", response_model=RecoverOut)
    def recover(body: RecoverIn):
        out = recover_uc.execute(identity_hash=_hid(body.identityHash), did=body.did)
        return RecoverOut(
            did=out.did, rebuilt=out.rebuilt, cmi=out.cmi,
            buildDigest=out.build_digest, buildDigestChanged=out.build_digest_changed,
            note=out.note,
        )

    @app.post("/v1/agents/sweep")
    def sweep():
        """到期清扫：只冻不删。放在独立端点，不夹在"查看"里顺手做。"""
        return {"frozen": recover_uc.sweep()}


# ---------------------------------------------------------------------------


def _hid(value: str) -> int:
    s = value.strip().lower().removeprefix("0x")
    if len(s) != 64:
        raise IssueRejected("identityHash 必须是 64 位十六进制")
    return int(s, 16)


def _digest(sel: Selection) -> str:
    from ..domain.entities import digest_selection

    return digest_selection(sel)


def _nonce() -> str:
    import secrets

    return secrets.token_hex(16)


def _summarise(items, ttl_hours: int) -> str:
    """给用户看的那一句：确认的是"哪些能力、用多久"，不是"是否确认"。"""
    names = "、".join(f"{i.moduleId} v{i.version}" for i in items)
    return f"将派生子智能体，能力：{names}；有效期 {ttl_hours} 小时。确认后才会开始生成。"


__all__ = ["install_routes", "_HttpMapping"]
