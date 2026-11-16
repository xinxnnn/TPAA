"""User-local OpenAI-compatible model settings for an issued AG2 agent.

Only process environment supplies the key. No model credential is written into
PHC, publication, manifest, issued files, or the local execution receipt.
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit


def from_env():
    model = os.environ.get("TPAA_AGENT_MODEL", "").strip()
    key = os.environ.get("TPAA_AGENT_API_KEY", "").strip()
    base_url = os.environ.get("TPAA_AGENT_BASE_URL", "").strip().rstrip("/")
    if not all((model, key, base_url)):
        raise ValueError("请在用户本机设置 TPAA_AGENT_MODEL、TPAA_AGENT_API_KEY 和 TPAA_AGENT_BASE_URL")
    parts = urlsplit(base_url)
    if (parts.username or parts.password or parts.query or parts.fragment or not parts.hostname
            or parts.scheme not in {"http", "https"}
            or (parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "::1", "localhost"})):
        raise ValueError("模型 API 地址必须使用 HTTPS，或仅使用本机 loopback HTTP")
    from ag2.config import OpenAICompletionsConfig
    return OpenAICompletionsConfig(model=model, api_key=key, base_url=base_url)


__all__ = ["from_env"]
