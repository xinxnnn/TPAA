"""Validate the party-based services layout and crypto client boundary."""

from __future__ import annotations

import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "services"

SIDES: dict[str, list[str]] = {
    "user_side": ["portal_api", "order_service", "agent_vault"],
    "tp_side": ["identity_service", "review_service", "phc_service", "did_service", "supervision_service"],
    "ap_side": ["agent_service", "subagent_service", "lifecycle_service"],
    "cross_domain": ["gateway", "policy_service", "audit_service", "coordination"],
    "ipfs": ["storage_service"],
}

LAYERS = [
    "api",
    "domain", "domain/entities", "domain/usecases", "domain/ports",
    "infra", "events", "tests",
]


def test_service_dirs_exist():
    for side, services in SIDES.items():
        for svc in services:
            base = BACKEND / side / svc
            assert base.is_dir(), f"缺少服务目录: {base}"
            for layer in LAYERS:
                assert (base / layer).is_dir(), f"{svc} 缺少分层目录 {layer}"
            if side != "ipfs":
                assert (base / "crypto_client").is_dir()
            assert (base / "app.py").is_file(), f"{svc} 缺少 app.py"
            if side == "ipfs":
                assert not (base / "crypto_client").exists(), "IPFS must not access crypto"


def test_crypto_client_only_sdk():
    """crypto_client imports crypto.sdk without bypassing its boundary."""
    import re

    illegal = re.compile(
        r'(?:from\s+crypto\.(?:phc|derivation|envelope|primitives)(?:\.\w+)?\s+import'
        r'|import\s+crypto\.(?:phc|derivation|envelope|primitives))'
    )
    for side, services in SIDES.items():
        for svc in services:
            if side == "ipfs":
                continue
            cc = BACKEND / side / svc / "crypto_client" / "__init__.py"
            src = cc.read_text(encoding="utf-8")
            assert not illegal.search(src), f"{svc} crypto_client 越权 import 内部实现"
            assert "crypto.sdk" in src, f"{svc} crypto_client 未引用 crypto.sdk"


def test_app_importable():
    for side, services in SIDES.items():
        for svc in services:
            mod = importlib.import_module(f"services.{side}.{svc}.app")
            assert hasattr(mod, "app"), f"{svc} app.py 未定义 app"


def test_build_app_optional():
    from services.shared.app_base import build_app

    app = build_app(title="skeleton", domain="tp_side")
    # 未装 FastAPI 时返回 None（骨架阶段允许）；装了则是 FastAPI 实例
    assert app is None or app.__class__.__name__ == "FastAPI"
