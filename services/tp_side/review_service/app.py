"""review-service —— TP 侧人工审核（tpaa_v1，errata E17）。

    POST /v1/reviews/{applicationId}   [reviewer]  提交判定（approve / reject）
    GET  /v1/reviews/{applicationId}   [reviewer / tp-operator]  审核进度
    GET  /v1/keys                       审批证据的验签公钥（公开）

★ 审核员身份取自令牌的 sub（= 人员名录里的 id，登录时由其个人 STAFF 密钥签名证明），
  请求体里**没有** reviewer 字段 —— 填两个名字凑双人的路被堵死了。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Body, FastAPI

from services.shared.store import JsonStore
from services.shared.v1_http import LazyApp, SystemClock, hex_pk, install_errors

from .domain.usecases.decide import ReviewDesk


@dataclass
class ReviewContext:
    review_hsm: object
    identity: object            # identity-service 的进程内端口（digest_of / mark）
    store: JsonStore
    clock: object = field(default_factory=SystemClock)


def build_context(*, review_hsm, identity, db_path: str, clock=None) -> ReviewContext:
    if getattr(review_hsm, "domain", None) != "REVIEW":
        raise RuntimeError("review-service 只用 REVIEW 域的签名密钥，不得注入 TP 协议 HSM")
    return ReviewContext(review_hsm=review_hsm, identity=identity, store=JsonStore(db_path),
                         clock=clock or SystemClock())


def create_app(*, ctx: ReviewContext, verifier) -> FastAPI:
    """reviewer：由 TP 域身份名录认证的一名审核员即可批准或驳回。"""
    app = FastAPI(title="review-service", version="1.0.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    app.state.desk = desk = ReviewDesk(ctx)
    install_errors(app)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "review-service", "profile": "tpaa_v1"}

    @app.get("/v1/keys")
    def keys():
        return {"signPk": hex_pk(ctx.review_hsm.pubkey())}

    @app.post("/v1/reviews/{app_id}")
    def decide(app_id: str, decision: str = Body(...), note: str = Body(""),
               who: dict = verifier.require("reviewer")):
        return desk.decide(app_id=app_id, reviewer=who["sub"], decision=decision, note=note)

    @app.get("/v1/reviews/{app_id}")
    def status(app_id: str, _: dict = verifier.require("reviewer", "tp-operator")):
        return desk.status(app_id)

    return app


def _from_env():
    raise RuntimeError(
        "review-service 需要 identity-service 的端口；当前只支持与 TP 其他服务同进程装配"
        "（见 tests/integration/test_tpaa_v1_http.py 的 TpDomain），独立部署待接 HTTP 端口")


app = LazyApp(_from_env)

__all__ = ["create_app", "build_context", "ReviewContext", "app"]
