"""phc-service —— TP 侧 PHC 签发与 D6 最终绑定（tpaa_v1）。

    POST /v1/phc/{applicationId}/issue      G2-b / G3：验审批证据 → 签发 → 返回 RR 密文
    POST /v1/phc/{applicationId}/finalize   D6：收 DIDGR 密文 → 返回 FINAL 密文

依赖（进程内端口，同在 TP 域）：
    identity   opened_for_issue / mark
    review     approval_for
AP 只以公钥材料出现：签名公钥、变色龙公钥（PublicChameleon）、加密公钥。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Body, FastAPI

import crypto.sdk
from services.shared.store import JsonStore
from services.shared.v1_http import LazyApp, SystemClock, install_errors

from .domain.usecases.issue import PhcDesk


@dataclass
class PhcContext:
    tp_hsm: object
    identity: object
    review: object
    review_pk: object
    sup_pub: object
    storage: object
    ap_sign_pk: object
    ap_ch: object
    ap_enc_pk: int
    domain1: str
    store: JsonStore
    clock: object = field(default_factory=SystemClock)
    allow_demo_scid_reveal: bool = False


def build_context(*, tp_hsm, identity, review, review_pk, sup_pub, storage, ap_bundle: dict,
                  domain1: str, db_path: str, clock=None,
                  allow_demo_scid_reveal: bool = False) -> PhcContext:
    """ap_bundle 是 AP 发布的公钥包（agent-service GET /v1/tpaa/keys）：
    {"signPk": hex, "chameleonCpk": hex, "encPub": hex}。只有公钥，没有任何陷门。"""
    if getattr(tp_hsm, "domain", None) != "TP":
        raise RuntimeError("phc-service 需要 TP 域的 HSM")
    v1 = crypto.sdk.v1
    return PhcContext(
        tp_hsm=tp_hsm, identity=identity, review=review, review_pk=review_pk,
        sup_pub=sup_pub, storage=storage,
        ap_sign_pk=v1.pk_from_hex(ap_bundle["signPk"]),
        ap_ch=crypto.sdk.public_from_hex(ap_bundle["chameleonCpk"]),
        ap_enc_pk=int(ap_bundle["encPub"], 16),
        domain1=domain1, store=JsonStore(db_path), clock=clock or SystemClock(),
        allow_demo_scid_reveal=allow_demo_scid_reveal)


def create_app(*, ctx: PhcContext, verifier) -> FastAPI:
    """issue / finalize 只允许申请人本人（或 TP 运营）调用。

    协议层已经保证"结果只有申请人解得开"（RR / FINAL 用用户公钥加密），
    这里再挡一道：别人不能替你触发签发、把你的申请推进到下一个状态。
    """
    from services.shared.v1_auth import require_owner

    app = FastAPI(title="phc-service", version="1.0.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    app.state.desk = desk = PhcDesk(ctx)
    install_errors(app)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "phc-service", "profile": "tpaa_v1"}

    @app.get("/v1/phc/keys")
    def public_parameters():
        public = ctx.sup_pub
        return {"paillier": {"n": format(public.n, "x"), "g1": format(public.g, "x")},
                "purpose": "supervision-irf-ecid"}

    @app.get("/v1/phc/reviewer-queue")
    def reviewer_queue(who: dict = verifier.require("reviewer")):
        return desk.reviewer_queue()

    @app.get("/v1/phc/did-directory")
    def did_directory(who: dict = verifier.require("reviewer", "supervisor")):
        return desk.did_directory()

    @app.post("/v1/phc/{app_id}/issue")
    def issue(app_id: str, who: dict = verifier.require("user", "tp-operator")):
        require_owner(who, ctx.identity.owner_of(app_id), operator_roles=("tp-operator",))
        return desk.issue(app_id=app_id)

    @app.post("/v1/phc/{app_id}/finalize")
    def finalize(app_id: str, didgr: dict = Body(..., embed=True),
                 who: dict = verifier.require("user")):
        require_owner(who, ctx.identity.owner_of(app_id))
        return desk.finalize(app_id=app_id, didgr=didgr)

    @app.get("/v1/phc/{app_id}")
    def status(app_id: str, who: dict = verifier.require("user", "tp-operator")):
        """只读签发状态，供下游对账用。

        ★ 为什么需要它：`/issue` 不幂等（已签发返回 409），下游失败后不能靠重放
          判断"上游到底签了没有"。这里只返回公开事实，不返回 RR / 记录内部字段。
        """
        require_owner(who, ctx.identity.owner_of(app_id), operator_roles=("tp-operator",))
        return desk.status(app_id=app_id)

    @app.get("/v1/phc/{app_id}/scid-demo")
    def scid_demo(app_id: str, who: dict = verifier.require("user")):
        require_owner(who, ctx.identity.owner_of(app_id))
        return desk.scid_demo(app_id=app_id, caller=who["sub"])

    return app


def _from_env():
    raise RuntimeError(
        "phc-service 需要 identity / review 的端口；当前只支持与 TP 其他服务同进程装配"
        "（见 tests/integration/test_tpaa_v1_http.py 的 TpDomain），独立部署待接 HTTP 端口")


app = LazyApp(_from_env)

__all__ = ["create_app", "build_context", "PhcContext", "app"]
