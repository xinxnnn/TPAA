#!/usr/bin/env python3
"""Scaffold TPAA services grouped by responsible party.

Only creates placeholder files; existing files are preserved unless --force is used.

    python scripts/gen_backend_skeleton.py [--force]
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES_ROOT = ROOT / "services"

SERVICES: dict[str, list[str]] = {
    "user_side": ["portal_api", "order_service", "agent_vault"],
    "tp_side": ["identity_service", "review_service", "phc_service", "did_service", "supervision_service"],
    "ap_side": ["agent_service", "subagent_service", "lifecycle_service"],
    "cross_domain": ["gateway", "policy_service", "audit_service", "coordination"],
    "ipfs": ["storage_service"],
}

LAYER_DIRS = [
    "api",
    "domain", "domain/entities", "domain/usecases", "domain/ports",
    "infra", "crypto_client", "events", "tests",
]

APP_TEMPLATE = '''"""{{service}} service scaffold ({{side}} domain).
Layering follows the service architecture: api / domain / infra / crypto_client / events.
Cryptographic operations must go through crypto.sdk, never crypto internals.
"""

from services.shared.app_base import build_app

app = build_app(title="{{service}}", domain="{{side}}")

__all__ = ["app"]
'''

CRYPTO_CLIENT_TEMPLATE = '''"""Only entry point for this service to call cryptographic capabilities.
❌ Forbidden: importing crypto internals directly (primitives / phc / derivation / envelope)
✅ Allowed: use crypto.sdk (or crypto.hsm). crypto.guard blocks boundary violations.

Import the namespace first (`import crypto.sdk`) and access APIs through it; do not use
`from crypto.sdk import ...`, which obscures the cryptographic boundary for the guard.
"""

import crypto.sdk

__all__ = ["crypto"]
'''

INIT_DOC = '"""{{path}} service layer placeholder."""\n'


def _write(p: Path, content: str, force: bool) -> None:
    if p.exists() and not force:
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    _write(SERVICES_ROOT / "__init__.py",
           '"""TPAA services grouped by responsible party."""\n', args.force)
    _write(SERVICES_ROOT / "shared" / "__init__.py",
           '"""Shared service infrastructure and adapters."""\n', args.force)
    _write(SERVICES_ROOT / "ipfs" / "__init__.py",
           '"""IPFS fifth-party service package."""\n', args.force)

    for side, services in SERVICES.items():
        _write(SERVICES_ROOT / side / "__init__.py",
               f'"""{side} service collection."""\n', args.force)
        for svc in services:
            if side == "ipfs":
                base = SERVICES_ROOT / "ipfs" / "storage_service"
                _write(base / "__init__.py", '"""IPFS encrypted-object storage service."""\n', args.force)
                _write(base / "app.py", '"""IPFS storage HTTP service scaffold."""\n', args.force)
                _write(base / "app.py", '"""IPFS storage HTTP service scaffold."""\n', args.force)
                for layer in ("api", "domain", "domain/entities", "domain/usecases", "domain/ports", "infra", "events", "tests"):
                    _write(base / layer / "__init__.py", INIT_DOC.replace("{{path}}", f"ipfs/storage_service/{layer}"), args.force)
                continue
            base = SERVICES_ROOT / side / svc
            _write(base / "__init__.py",
                   f'"""{svc} service package ({side})."""\n', args.force)
            _write(base / "app.py",
                   APP_TEMPLATE.replace("{{service}}", svc).replace("{{side}}", side),
                   args.force)
            _write(base / "crypto_client" / "__init__.py",
                   CRYPTO_CLIENT_TEMPLATE, args.force)
            for layer in LAYER_DIRS:
                _write(base / layer / "__init__.py",
                       INIT_DOC.replace("{{path}}", f"{side}/{svc}/{layer}"),
                       args.force)

    print("service skeletons: " + ", ".join(
        f"{side}={len(services)}" for side, services in SERVICES.items()
    ) + f"; total={sum(len(v) for v in SERVICES.values())}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
