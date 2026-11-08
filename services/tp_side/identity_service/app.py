"""identity-service —— TP 侧身份材料受理（tpaa_v1 G2-a）。

    POST /v1/auth/challenge | login       TP 域登录（见 services/shared/v1_auth.py）
    GET  /v1/keys                         TP 的加密公钥与签名公钥（公开）
    POST /v1/slots                        [user]     为自己的签名公钥分配 TP 陷门槽位
    POST /v1/applications                 [user]     提交 CR 密文（签名人必须是登录用户）
    GET  /v1/applications/{id}/review     [reviewer] 审核视图（PII 掩码，BI 只列项目），查看留痕

传输层仍需 TLS；审核视图应只在 TP 内网开放（令牌是第一道，网络策略是第二道）。
"""

from __future__ import annotations

import crypto.sdk
from fastapi import Body, FastAPI

from services.shared.v1_auth import install_auth_routes
from services.shared.v1_http import LazyApp, hex_pk, install_errors

from .domain.usecases.intake import IdentityIntake


def create_app(*, ctx, auth) -> FastAPI:
    """auth：TP 域的 AuthIssuer。identity-service 是 TP 域的登录入口（/v1/auth/*）。"""
    app = FastAPI(title="identity-service", version="1.0.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    app.state.intake = uc = IdentityIntake(ctx)
    install_errors(app)
    install_auth_routes(app, auth)
    guard = auth.verifier()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "identity-service", "profile": "tpaa_v1"}

    @app.get("/v1/keys")
    def keys():
        # 公钥，公开
        return {"encPub": format(ctx.tp_hsm.enc_pub(), "x"), "signPk": hex_pk(ctx.tp_hsm.pubkey()),
                "chameleonCpk": crypto.sdk.ser_point(ctx.tp_hsm.chameleon_cpk()).hex()}

    @app.post("/v1/slots")
    def slots(userSignPk: str = Body(..., embed=True), who: dict = guard.require("user")):
        return uc.allocate_slot(user_sign_pk_hex=userSignPk, caller=who["sub"])

    @app.post("/v1/applications")
    def submit(cr: dict = Body(..., embed=True), who: dict = guard.require("user")):
        return uc.submit(cr_box=cr, caller=who["sub"])

    @app.get("/v1/applications/{app_id}/timeline")
    def timeline(app_id: str, who: dict = guard.require("user")):
        base = uc.progress(app_id, caller=who["sub"])
        events = [{"stage": "G1", "status": "accepted_by_tp", "at": base["receivedAt"],
                   "artifacts": {"applicationId": app_id, "crDigest": base["crDigest"]}}]
        review = base["review"]
        if review:
            events.append({"stage": "REVIEW", "status": review["state"],
                           "at": review["decisions"][-1]["at"] if review["decisions"] else base["receivedAt"],
                           "artifacts": {"approved": review["approved"],
                                         "decisions": review["decisions"]}})
        return {"applicationId": app_id, "state": base["state"], "events": events}

    @app.get("/v1/applications/{app_id}/decrypted-demo")
    def decrypted_demo(app_id: str, who: dict = guard.require("user")):
        return uc.decrypted_demo_view(app_id, caller=who["sub"])

    @app.post("/v1/applications/review-queue")
    def review_queue(who: dict = guard.require("reviewer")):
        ctx.audit("identity.review_queue_viewed", "", {"by": who["sub"]})
        return uc.review_queue()

    @app.get("/v1/applications/{app_id}/review")
    def review(app_id: str, who: dict = guard.require("reviewer")):
        ctx.audit("identity.review_viewed", app_id, {"by": who["sub"]})
        return uc.review_view(app_id)

    return app


def _from_env():
    import json
    from pathlib import Path

    from services.shared.v1_auth import AuthIssuer
    from services.shared.v1_http import (SystemClock, assert_single_worker, env_required,
                                         hsm_from_seed)

    from .infra.wiring import IdentityEvidencePolicy, build_context

    assert_single_worker("identity-service")
    clock = SystemClock()
    staff = json.loads(Path(env_required("TPAA_TP_STAFF")).read_text(encoding="utf-8"))
    trust = json.loads(Path(env_required("TPAA_IDENTITY_VERIFIER_TRUST")).read_text(encoding="utf-8"))
    policy = IdentityEvidencePolicy(trusted_issuers=trust["issuers"],
                                    min_assurance=trust.get("minAssurance", "substantial"))
    return create_app(
        ctx=build_context(tp_hsm=hsm_from_seed("TP"), db_path=env_required("TPAA_IDENTITY_DB"),
                          clock=clock, identity_policy=policy),
        auth=AuthIssuer(issuer_hsm=hsm_from_seed("AUTH"), aud="tpaa:tp", clock=clock,
                        staff=staff))


app = LazyApp(_from_env)

__all__ = ["create_app", "app"]
