"""Portal startup failures should be reported as unavailable, not request 500s."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from services.user_side.portal_api.app import _PortalApp


def _broken_factory():
    raise RuntimeError("missing TPAA_EXECUTOR_TOKEN")


def test_portal_startup_failure_returns_safe_503_and_logs_diagnostic(caplog):
    app = _PortalApp(_broken_factory)
    response_messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        response_messages.append(message)

    import asyncio
    asyncio.run(app({"type": "http", "asgi": {"version": "3.0"},
                     "method": "GET", "path": "/api/user/v1/initialize",
                     "headers": [], "query_string": b"", "server": ("test", 80),
                     "client": ("test", 1), "scheme": "http"}, receive, send))

    start = next(message for message in response_messages if message["type"] == "http.response.start")
    body = next(message for message in response_messages if message["type"] == "http.response.body")["body"]
    import json
    assert start["status"] == 503
    assert json.loads(body) == {
        "code": "PORTAL_NOT_READY",
        "message": "Portal 尚未就绪，请检查服务端启动配置与依赖服务",
    }
    assert "missing TPAA_EXECUTOR_TOKEN" in caplog.text
