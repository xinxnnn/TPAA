"""FastAPI app factory used by service scaffolds."""

from __future__ import annotations

try:
    from fastapi import FastAPI
except ImportError:  # pragma: no cover - 核心仓库测试环境可不装 FastAPI
    FastAPI = None  # type: ignore[assignment]


def build_app(*, title: str, domain: str):
    """Create a health-enabled scaffold app.

    domain identifies the responsible service group. Returns None when FastAPI
    is not installed, which is allowed for scaffold-only environments.
    """
    if FastAPI is None:
        return None
    app = FastAPI(title=title, version="0.1.0-skeleton")
    app.state.domain = domain

    @app.get("/healthz")
    def healthz():  # pragma: no cover - 由集成测试在装了 FastAPI 时覆盖
        return {"status": "ok", "service": title, "domain": domain}

    return app


__all__ = ["build_app", "FastAPI"]
