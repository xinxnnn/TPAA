"""gateway —— AP 侧唯一的对外出入口。

★ 它存在的理由不是"转发"，是**让 AP 这个角色真的出现在追溯链里**。

    在它之前，TP 开一张协查单，工单就躺在通道里等 —— 没有任何东西代表 AP 去应答。
    测试里那句"AP 答��了"其实是直接调通道的答复接口实现的，
    等于 TP 自己替 AP 答了一遍。追溯链上少了一方，而这一点从外部看不出来：
    工单状态是 answered，取证包里什么都有，只是那张证明是同一个人在两边签的字。

    gateway 把这个缺口补上：AP 主动去拉、在本地算、过自己的卡口、再送回去。

★ 为什么是"拉"而不是"被推送"：
    见 usecases/outbox 的说明。要点是边界上只有出站流量，
    AP 侧不需要开任何入站端口（吊销广播除外 —— 那是另一条路，且带案由）。
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .api.routes import _HttpMapping, install_routes


def create_app(*, ctx=None, **dev) -> FastAPI:
    if ctx is None:
        from .infra.wiring import build_dev_context

        ctx = build_dev_context(**dev)

    app = FastAPI(title="gateway", version="0.1.0")
    app.state.domain = "ap-side"
    app.state.ctx = ctx
    _HttpMapping().install(app)
    install_routes(app, ctx)
    return app


def _ctx_from_env():
    """生产装配。

    ★ 通道地址必填，且**没有默认值**。
      一个自动退回"本机进程内调用"的 gateway 会在配置漏配时安静地跑起来，
      看起来一切正常 —— 但它其实根本没跨进程，分区部署形同虚设，
      而这个问题要等到某次真实跨域协查失败时才会暴露。
    """
    from .infra.adapters import HttpChannel
    from .infra.wiring import build_context

    base = (os.environ.get("TPAA_COORD_BASE_URL") or "").strip()
    if not base:
        raise RuntimeError(
            "缺少环境变量 TPAA_COORD_BASE_URL（coordination 的地址）—— "
            "gateway 不会自动退回进程内调用：那会让分区部署在配置漏配时静默失效")

    raise RuntimeError(
        "gateway 的本地能力（assist / stop / audit）必须与 lifecycle-service、"
        "audit-service 共享上下文 —— 环境变量里只有地址，没有能力。\n"
        "  正确装配：create_app(ctx=build_context(\n"
        "      channel=HttpChannel(base_url=TPAA_COORD_BASE_URL),\n"
        "      assist=LocalAssist(lifecycle_ctx), stop=LocalStop(lifecycle_ctx),\n"
        "      audit=LocalAudit(audit_ctx), self_id='AP'))\n"
        "环境变量已读到的通道地址：" + base)


def _kinds_from_env() -> tuple:
    raw = (os.environ.get("TPAA_GATEWAY_KINDS") or "lineage_proof").strip()
    return tuple(k.strip() for k in raw.split(",") if k.strip())


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
