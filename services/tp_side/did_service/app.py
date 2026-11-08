"""did-service —— TP 侧的 DID 注册表。

分工：
    app.py        装配与 ASGI 入口
    api/          端点与错误映射
    domain/       登记 / 查询 / 上溯 / 撤销的规则
    infra/        落盘、时钟、装配

启动（生产）：
    TPAA_DID_DB 指向注册表文件；监管公钥由监管域注入 `create_app(pub=...)`。

本地演练：
    `create_app(dev_db=...)` 本地生成一对监管密钥并**当场丢弃私钥** ——
    本服务只负责封存，从不还原身份。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_db: str | None = None, pub=None) -> FastAPI:
    if ctx is None:
        if not dev_db:
            raise RuntimeError("create_app 需要 ctx（生产装配）或 dev_db（本地演练）之一")
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(db_path=dev_db)

    app = FastAPI(title="did-service", version="0.1.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    """生产装配：库路径与监管公钥模数 n 都来自环境。

    ★ 这里刻意**没有**"缺了就自己生成一把"的分支：
      自己生成的密钥重启即换，上一轮封存的 CSCID 会全部解不开，
      而这种故障要等到第一次真正追溯时才暴露 —— 那时已经晚了。
      缺参数就在启动阶段拒绝，让它在部署时被人看见。

    n 是公开值，进环境变量不算泄密；需要保密的那半边永远留在监管域。
    """
    import crypto.sdk

    from .infra.wiring import build_context

    db = (os.environ.get("TPAA_DID_DB") or "").strip()
    if not db:
        raise RuntimeError("缺少环境变量 TPAA_DID_DB（DID 注册表路径）")
    n_raw = (os.environ.get("TPAA_SUPERVISION_PUB_N") or "").strip()
    if not n_raw:
        raise RuntimeError(
            "缺少环境变量 TPAA_SUPERVISION_PUB_N（监管公钥模数 n，十进制）—— "
            "它由监管域发布；本服务只用它封存 H(ID)，无权还原")

    return build_context(db_path=db,
                         supervision_pub=crypto.sdk.supervision_public_from_n(n_raw))


class _LazyApp:
    """模块级 `app` 的惰性占位 —— 理由同 agent-service：
    import 不该建库、不该生成密钥。装配推迟到真正提供服务的那一刻。
    """

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
