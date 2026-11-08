"""coordination —— TP ↔ AP 的唯一协查通道。

它不属于任何一方：TP 与 AP 都可以用它，但又都不能改它。
这条性质在代码里体现为：它的领域模型里没有 "did"、没有 "phc"、没有任何一方的术语，
只有"谁问了谁、问什么类别、答了什么"。通道不认识业务，才不会偏袒业务。
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

    app = FastAPI(title="coordination", version="0.1.0")
    app.state.domain = "cross-domain"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    """生产装配：库路径来自环境，审计归档**必须**由部署注入。

    ★ 这里不会自动退回内存审计 —— 那会让一个生产通道在"忘记接审计"时
      安静地跑起来，而协查留痕恰恰是取证包的一环。缺了就起不来。
    """
    from .infra.audit import NotImplementedAudit
    from .infra.wiring import build_context, quota_from_env

    db = (os.environ.get("TPAA_COORD_DB") or "").strip()
    if not db:
        raise RuntimeError("缺少环境变量 TPAA_COORD_DB（工单库路径）")
    return build_context(db_path=db, audit=NotImplementedAudit(),
                         quota=quota_from_env())


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
