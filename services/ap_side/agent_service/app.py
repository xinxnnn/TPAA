"""agent-service —— ap-side 的智能体申领 / 派生 / 找回服务。

分工：
    app.py        组装（谁装进来）
    api/routes.py 端点与错误映射（请求怎么进、拒绝怎么出）
    domain/       业务规则（允许做什么、不许做什么）
    infra/        端口实现（TP、IPFS、时钟）
    crypto_client 密码边界的唯一入口

启动方式（生产）：
    TPAA_STORE_ROOT / TPAA_INDEX_KEY / TPAA_ECID_KEY 必须由部署注入，
    并通过 `create_app(ctx=...)` 传入已装配好的上下文。

本地演练：
    `create_app(dev_store=...)` 自动生成 HSM 与密钥 —— 只用于测试。
"""

from __future__ import annotations

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, dev_store: str | None = None,
               storage=None, clock=None) -> FastAPI:
    """构造应用。ctx 与 dev_store 二选一。

    ★ 刻意不提供"什么参数都不给也能起"的路径：
      没有上下文的服务能启动，就意味着有人会以为它可以工作，
      然后排障一小时才发现是装配没做。宁可起不来。
    """
    if ctx is None:
        if not dev_store:
            raise RuntimeError(
                "create_app 需要 ctx（生产装配）或 dev_store（本地演练）之一")
        from .infra.wiring import build_dev_context
        from services.ipfs.storage_service.app import StorageService


        ctx = build_dev_context(
            store_root=dev_store,
            storage=storage if storage is not None else StorageService(),
            clock=clock,
        )

    app = FastAPI(title="agent-service", version="0.2.0")
    app.state.domain = "ap-side"
    app.state.ctx = ctx

    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    """生产装配：全部参数来自环境变量，缺一项就拒绝启动。

    HSM 密钥经 `TPAA_HSM_SEED`（种子文件）注入，见 `load_hsm_seed`。
    种子文件是演练形态；接真实 HSM/KMS 时只替换 `load_hsm_seed`，接口不变。
    """
    from services.ipfs.storage_service.app import StorageService
    from services.shared.v1_http import assert_single_worker

    from .infra.wiring import InfraConfig, build_context, load_hsm_seed

    assert_single_worker("agent-service")
    cfg = InfraConfig.from_env()
    # ★ 以前这里每次启动都 make_demo_hsm() 生成新密钥 ——
    #   重启一次，库里所有 PHC 就验签失败。现在密钥必须来自注入，缺了拒绝启动。
    tp_hsm, ap_hsm = load_hsm_seed()
    return build_context(
        config=cfg, tp_hsm=tp_hsm, ap_hsm=ap_hsm, storage=StorageService(),
    )


__all__ = ["create_app", "app"]


class _LazyApp:
    """模块级 `app` 的惰性占位。

    ★ 为什么不是 `app = create_app(dev_store=...)`：
      import 这个模块不该产生副作用 —— 它会被测试、脚本、工具反复 import，
      每一次都建目录、生成密钥、写索引，是灾难。
    ★ 为什么还要有 `app` 这个属性：
      ASGI 服务器约定按 `module:app` 找实例（uvicorn agent-service.app:app）。
      没有它，部署脚本就得改成工厂调用，而"工厂格式"各家互不相同。
    所以这里给一个**只在第一次被访问时才装配**的代理：
      - 读环境变量、装配、自检，全部推迟到真正提供服务的那一刻
      - 环境变量缺失时在启动阶段就报错，而不是在第一个请求里
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


# ASGI 入口：`uvicorn ... <模块路径>:app`
app = _LazyApp()
