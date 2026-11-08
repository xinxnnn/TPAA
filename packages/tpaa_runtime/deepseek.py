"""DeepSeek provider adapter for the local AG2 demo.

Uses the official DeepSeek REST endpoint directly. The API key is read from the
process environment and never returned to the browser or stored in the manifest.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class DeepSeekError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeepSeekConfig:
    api_key: str
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"
    timeout: float = 90.0

    @classmethod
    def from_env(cls) -> "DeepSeekConfig":
        key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        if not key:
            raise DeepSeekError("缺少 DEEPSEEK_API_KEY；请在启动 AG2 服务前设置环境变量")
        return cls(
            api_key=key,
            model=(os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat").strip(),
            base_url=(os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/"),
        )


def chat_completion(*, config: DeepSeekConfig, messages: list[dict[str, Any]],
                    tools: list[dict[str, Any]] | None = None,
                    temperature: float = 0.2) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    request = urllib.request.Request(
        f"{config.base_url}/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise DeepSeekError(f"DeepSeek HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise DeepSeekError(f"DeepSeek 网络连接失败：{exc.reason}") from exc
    except TimeoutError as exc:
        raise DeepSeekError("DeepSeek 请求超时") from exc
    try:
        return body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise DeepSeekError(f"DeepSeek 返回格式异常：{body!r}") from exc


__all__ = ["DeepSeekConfig", "DeepSeekError", "chat_completion"]
