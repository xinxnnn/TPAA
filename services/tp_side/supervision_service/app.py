"""supervision-service —— TP 侧的立案、协查、揭露、取证。

它是整条追溯链的**闸门**：一个人能不能被还原、什么时候能被还原，
只有这里说了算。所以它的状态机比别的服务都硬，
而它的密钥是全系统唯一能打开 CSCID 的那一把。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_db: str | None = None, **deps) -> FastAPI:
    if ctx is None:
        if not dev_db:
            raise RuntimeError(
                "create_app 需要 ctx（生产装配）或 dev_db + 依赖（本地演练）之一")
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(db_path=dev_db, **deps)

    app = FastAPI(title="supervision-service", version="0.1.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    """生产装配必须由监管域注入密钥与四个端口的实现。

    ★ 这里刻意不提供"自动装配"路径：
      一个能自己拼出监管密钥的服务，等于把"谁有权还原身份"这个问题
      降级成一个环境变量配得对不对的问题。
      缺了就在启动阶段报错，让它在部署时被人看见。
    """
    db = (os.environ.get("TPAA_CASE_DB") or "").strip()
    if not db:
        raise RuntimeError("缺少环境变量 TPAA_CASE_DB（案件库路径）")
    raise RuntimeError(
        "supervision-service 必须由监管域显式装配："
        "create_app(ctx=build_context(key=..., directory=..., channel=..., "
        "storage=..., audit=...))")


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
