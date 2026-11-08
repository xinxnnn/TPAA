"""门户认证边界的行为测试。

钉死三件事：
    1. 门户不持有 TP / AP 的 auth issuer 种子（B1 的全部意义）
    2. 门户为用户区签的令牌，TP / AP 不认（域隔离真的生效，不是靠约定）
    3. 生产装配不声称"用户控制执行"（`keys.json` 明文密钥不是 custody）
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("fastapi")

import crypto.sdk  # noqa: E402
from services.shared.v1_auth import AuthIssuer, Unauthenticated  # noqa: E402
from services.shared.v1_http import FixedClock  # noqa: E402

v1 = crypto.sdk.v1

PRODUCTION = ROOT / "services" / "user_side" / "portal_api" / "infra" / "production.py"


# ---------------------------------------------------------------------------
# 1. 门户不碰 TP / AP 的 auth 种子
# ---------------------------------------------------------------------------


def test_production_wiring_has_no_tp_or_ap_auth_seed():
    """源码级断言：这两个种子名不该出现在门户装配里。

    ★ 为什么用源码断言：这是"门户有没有能力冒充域"的问题。
      只要装配里能读到 TP/AP 的 AUTH 种子，门户就能自签任意角色的令牌 ——
      运行时测不出来，因为它可以只在被攻破时才用。
    """
    text = PRODUCTION.read_text(encoding="utf-8")
    for forbidden in ("TPAA_TP_AUTH_HSM_SEED", "TPAA_AP_AUTH_HSM_SEED"):
        assert forbidden not in text, f"门户装配不得引用 {forbidden}"


def test_production_wiring_logs_in_through_executor_signature():
    """门户取域令牌的唯一路径是 challenge → 执行器签名 → login。"""
    text = PRODUCTION.read_text(encoding="utf-8")
    assert "/v1/auth/challenge" in text
    assert "/v1/auth/login" in text
    assert "executor.login_body" in text, "登录签名必须由执行器做，门户不持用户密钥"


def test_portal_context_carries_no_domain_issuer():
    """装配出来的上下文里，上游端口只有 URL 和执行器，没有 TP/AP issuer 对象。"""
    import inspect

    from services.user_side.portal_api.infra.production import ServiceHttpPort

    fields = set(inspect.signature(ServiceHttpPort.__init__).parameters)
    assert "executor" in fields
    for leaked in ("issuer", "issuer_hsm", "hsm", "seed"):
        assert leaked not in fields, f"上游端口不该拿到 {leaked}"


# ---------------------------------------------------------------------------
# 2. 域隔离：门户签的用户区令牌，TP / AP 不认
# ---------------------------------------------------------------------------


def _issuer(aud: str, staff_pk: str) -> AuthIssuer:
    return AuthIssuer(issuer_hsm=v1.make_demo_hsm(domain="AUTH"), aud=aud,
                      clock=FixedClock(), staff={staff_pk: {"id": "u-1", "role": "user"}})


def test_portal_user_token_is_rejected_by_tp_and_ap():
    """★ 这是 B1 的核心行为：门户的令牌在 TP / AP 一侧验不过。

    两道独立的闸：aud 不同（tpaa:user vs tpaa:tp），签发方公钥也不同。
    """
    user = v1.make_demo_hsm(domain="USER")
    pk = v1.pk_hex(user.pubkey())
    portal = _issuer("tpaa:user", pk)
    tp = _issuer("tpaa:tp", pk)
    ap = _issuer("tpaa:ap", pk)

    token = f"Bearer {portal.token_for(pk)['token']}"
    for domain, issuer in (("tp", tp), ("ap", ap)):
        with pytest.raises(Exception) as caught:
            issuer.verifier().check(token)
        assert isinstance(caught.value, (Unauthenticated, v1.ProtocolError, PermissionError)), \
            f"{domain} 应当拒绝门户令牌，实际抛了 {type(caught.value).__name__}"


def test_token_from_one_domain_is_rejected_by_the_other():
    """TP 的令牌拿到 AP 去用也不行（反向同理）。"""
    user = v1.make_demo_hsm(domain="USER")
    pk = v1.pk_hex(user.pubkey())
    tp, ap = _issuer("tpaa:tp", pk), _issuer("tpaa:ap", pk)

    with pytest.raises(Exception):
        ap.verifier().check(f"Bearer {tp.token_for(pk)['token']}")
    with pytest.raises(Exception):
        tp.verifier().check(f"Bearer {ap.token_for(pk)['token']}")


def test_issuer_accepts_its_own_token():
    """反向对照：同域令牌必须验得过，否则上面的拒绝没有意义。"""
    user = v1.make_demo_hsm(domain="USER")
    pk = v1.pk_hex(user.pubkey())
    tp = _issuer("tpaa:tp", pk)
    claims = tp.verifier().check(f"Bearer {tp.token_for(pk)['token']}")
    assert claims["aud"] == "tpaa:tp"
    assert claims["role"] == "user"


# ---------------------------------------------------------------------------
# 3. 不声称用户控制执行
# ---------------------------------------------------------------------------


def test_production_profile_is_test_adapter():
    """生产装配写死 test-adapter —— 它用的是 keys.json 明文密钥。"""
    text = PRODUCTION.read_text(encoding="utf-8")
    assert 'execution_profile="test-adapter"' in text
    assert 'execution_profile="user-controlled"' not in text


def test_initialize_does_not_claim_user_controlled_execution():
    """initialize 的 userControlledExecution 必须随 profile 如实返回 false。"""
    from services.user_side.portal_api.app import PortalContext, PortalDesk

    class _Executor:
        owner = "fpr:deadbeef"

        def public_signing_key(self):
            return self._pk

    hsm = v1.make_demo_hsm(domain="USER")
    ex = _Executor()
    ex._pk = v1.pk_hex(hsm.pubkey())
    owner = v1.owner_of(hsm.pubkey())
    ex.owner = owner

    class _Port:
        def get(self, path):
            if path == "/v1/phc/keys":
                return {"paillier": {"n": "b", "g1": "c"}, "purpose": "test"}
            return {"signPk": "test", "chameleonCpk": "test", "encPub": "test"}

        def post(self, path, body, owner):
            return {}

    class _Store:
        def load(self):
            return {}

        def update(self, fn):
            return fn({})

    ctx = PortalContext(wallet_root=Path("."), store=_Store(), tp=_Port(), ap=_Port(),
                        phc=_Port(), agent=_Port(), auth=None, clock=FixedClock(),
                        handlers={owner: ex}, execution_profile="test-adapter")
    out = PortalDesk(ctx).initialize(owner)
    assert out["checks"]["executionProfile"] == "test-adapter"
    assert out["checks"]["userControlledExecution"] is False, \
        "test-adapter 下绝不能声称用户控制执行"


def test_handler_docstring_marks_itself_as_non_custody():
    """`UserCredentialHandler` 必须自己写明它不是生产 custody。"""
    from user_credential_handler.handler import UserCredentialHandler

    doc = (UserCredentialHandler.__module__, UserCredentialHandler.__doc__ or "")
    import importlib
    module_doc = importlib.import_module(doc[0]).__doc__ or ""
    text = (module_doc + doc[1]).lower()
    assert "not a user-controlled" in text or "not a production" in text, \
        "测试 adapter 必须在文档里标明自己不是生产密钥托管"
