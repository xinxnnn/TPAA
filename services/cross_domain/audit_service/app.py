"""audit-service —— 审计链与取证导出。

它不属于 TP 也不属于 AP：两边都往里写，谁都不能改。
这是"互相指责时唯一还算中立的那本账"。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_db: str | None = None) -> FastAPI:
    if ctx is None:
        if not dev_db:
            raise RuntimeError("create_app 需要 ctx（生产装配）或 dev_db（本地演练）之一")
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(db_path=dev_db)

    app = FastAPI(title="audit-service", version="0.1.0")
    app.state.domain = "cross-domain"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    from .infra.wiring import build_context

    db = (os.environ.get("TPAA_AUDIT_DB") or "").strip()
    if not db:
        raise RuntimeError("缺少环境变量 TPAA_AUDIT_DB（审计账本路径）")
    attest = (os.environ.get("TPAA_AUDIT_ATTEST_DB") or "").strip() or None
    return build_context(db_path=db, attest_path=attest)


class _LazyApp:
    _inner = None

    def _get(self):
        if _LazyApp._inner is None:
            _LazyApp._inner = create_app(ctx=_ctx_from_env())
        return _LazyApp._inner

    async def __call__(self, scope, receive, send):
        # ASGI3 三参签名：uvicorn 按签名嗅探版本，*a/**kw 会被当成 ASGI2。
        await self._get()(scope, receive, send)

    def __getattr__(self, name):
        return getattr(self._get(), name)


app = _LazyApp()

__all__ = ["create_app", "app"]
