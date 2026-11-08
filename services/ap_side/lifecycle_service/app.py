"""lifecycle-service —— AP 侧的升级 / 找回 / 停运编排。

★ 它没有任何密钥。这是刻意的：
  这个服务会被"网络上的吊销广播"触发，而一个能被外部触发、
  又持有密钥的服务，是整张架构里风险最高的一个点。
  把能力剥干净之后，即使广播通道被打穿，攻击者也只能改状态。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_store: str | None = None, agent_ctx=None) -> FastAPI:
    if ctx is None:
        if not (dev_store and agent_ctx):
            raise RuntimeError(
                "create_app 需要 ctx，或 dev_store + agent_ctx（本地演练）")
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(store_root=dev_store, agent_ctx=agent_ctx)

    app = FastAPI(title="lifecycle-service", version="0.1.0")
    app.state.domain = "ap-side"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    from .infra.wiring import build_context

    root = (os.environ.get("TPAA_STORE_ROOT") or "").strip()
    if not root:
        raise RuntimeError("缺少环境变量 TPAA_STORE_ROOT（localstore 根）")
    raise RuntimeError(
        "lifecycle-service 必须与 agent-service 共享上下文："
        "create_app(ctx=build_context(store_root=..., agent_ctx=...))")


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
