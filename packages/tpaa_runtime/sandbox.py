"""AG2 本地 Tool Gateway 与对话沙盒。

本阶段不接真实 LLM/API：对话解释器是确定性的命令路由器，目的是验证：
    manifest → capability → tool policy → 用户确认 → 执行 → 审计

未来接 LLM 时，LLM 只能产生"候选工具调用"，仍必须经 ToolGateway。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from .manifest import AgentManifest, ManifestError


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    agent_did: str
    manifest_digest: str
    tool_id: str
    operation: str
    request_digest: str
    status: str
    user_confirmed: bool
    detail: str = ""


@dataclass
class ToolGateway:
    manifest: AgentManifest
    handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = field(default_factory=dict)
    audit: list[AuditEvent] = field(default_factory=list)
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    state_check: Callable[[], bool] = lambda: True

    def preflight(self) -> None:
        self.manifest.validate()
        if not self.state_check():
            raise GatewayError("PHC / DID 状态检查失败，AG2 不允许运行")

    def _tool(self, tool_id: str):
        for tool in self.manifest.tools:
            if tool.id == tool_id:
                return tool
        raise GatewayError(f"工具未在 manifest 中声明：{tool_id}")

    def request(self, tool_id: str, operation: str, args: dict[str, Any], *, confirmed: bool = False) -> dict:
        self.preflight()
        tool = self._tool(tool_id)
        if tool.allowed_operations and operation not in tool.allowed_operations:
            raise GatewayError(f"工具 {tool_id} 不允许操作 {operation}")
        if tool.requires_confirmation and not confirmed:
            request_id = "confirm-" + secrets.token_hex(8)
            self.pending[request_id] = {"toolId": tool_id, "operation": operation, "args": args}
            return {"status": "confirmation_required", "requestId": request_id,
                    "toolId": tool_id, "operation": operation, "args": args}
        handler = self.handlers.get(tool_id)
        if handler is None:
            raise GatewayError(f"工具没有本地连接器：{tool_id}")
        result = handler(args)
        request_digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()
        self.audit.append(AuditEvent(
            event_id="evt-" + secrets.token_hex(8), agent_did=self.manifest.did,
            manifest_digest=self.manifest.digest(), tool_id=tool_id, operation=operation,
            request_digest=request_digest, status="success", user_confirmed=confirmed,
        ))
        return {"status": "completed", "result": result}

    def confirm(self, request_id: str) -> dict:
        pending = self.pending.get(request_id)
        if pending is None:
            raise GatewayError("确认请求不存在或已使用")
        result = self.request(pending["toolId"], pending["operation"], pending["args"], confirmed=True)
        self.pending.pop(request_id, None)
        return result


class LocalConversation:
    """不依赖 LLM 的本地演示对话。

    支持：
        "摘要 <text>" → summarize.run
        "检索 <query>" → knowledge.search
        "创建日历 <title>" → 需要用户确认
    """

    def __init__(self, gateway: ToolGateway) -> None:
        self.gateway = gateway
        self.history: list[dict[str, str]] = []

    def send(self, text: str) -> dict:
        self.history.append({"role": "user", "content": text})
        if text.startswith("摘要 "):
            result = self.gateway.request("summarize.run", "run", {"text": text[3:]})
            return self._answer("已通过 Tool Gateway 调用摘要能力。", result)
        if text.startswith("检索 "):
            result = self.gateway.request("knowledge.search", "search", {"query": text[3:]})
            return self._answer("已通过 Tool Gateway 调用本地知识检索。", result)
        if text.startswith("创建日历 "):
            result = self.gateway.request("calendar.create", "create_event", {"title": text[5:]})
            if result["status"] == "confirmation_required":
                return self._answer("这是高风险操作，需要用户确认后才能执行。", result)
            return self._answer("日历事件已创建。", result)
        return self._answer("本地沙盒支持：摘要、检索、创建日历。", {"status": "no_tool"})

    def confirm(self, request_id: str) -> dict:
        return self._answer("用户确认后工具已执行。", self.gateway.confirm(request_id))

    def _answer(self, text: str, payload: dict) -> dict:
        self.history.append({"role": "assistant", "content": text})
        return {"message": text, **payload}


__all__ = ["GatewayError", "AuditEvent", "ToolGateway", "LocalConversation"]
