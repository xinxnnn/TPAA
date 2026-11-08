"""policy-service —— 凭证策略、吊销广播、按 parent_did 级联。

它不掌握"谁是后代"（那是 did-service 的事），也不掌握"实例在不在跑"
（那是 AP 侧 lifecycle-service 的事）。它只做一件事：
**把一条有案由的吊销令，拆成两段可重试的动作，并保证顺序**。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_db: str | None = None, **deps) -> FastAPI:
    if ctx is None:
        if not dev_db:
            raise RuntimeError("create_app 需要 ctx（生产装配）或 dev_db + 依赖 之一")
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(db_path=dev_db, **deps)

    app = FastAPI(title="policy-service", version="0.1.0")
    app.state.domain = "cross-domain"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    db = (os.environ.get("TPAA_POLICY_DB") or "").strip()
    if not db:
        raise RuntimeError("缺少环境变量 TPAA_POLICY_DB（吊销令库路径）")
    raise RuntimeError(
        "policy-service 需要显式装配三个端口："
        "create_app(ctx=build_context(directory=..., notify=..., audit=...))")


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
