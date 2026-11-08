"""AG2 manifest / Tool Gateway / local conversation sandbox tests."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

from tpaa_runtime.manifest import Capability, ManifestError, ToolDeclaration, build_manifest  # noqa: E402
from tpaa_runtime.sandbox import GatewayError, LocalConversation, ToolGateway  # noqa: E402


def _manifest():
    return build_manifest(
        did="did:wba:test:tp:ap", phc_digest="a" * 64, issuer="tp", af_ref="b" * 64,
        modules=[("summarize", "1.0.0", "aa" * 32)],
        capabilities=[Capability("summarize", "1.0.0", "摘要")],
        tools=[ToolDeclaration("summarize.run", "summarize", "摘要", allowed_operations=("run",))],
    )


def test_manifest_contains_phc_cmi_and_build_binding():
    m = _manifest()
    m.validate()
    data = m.to_json()
    assert data["phc"]["profile"] == "tpaa_v1"
    assert data["ownerBinding"]["afRef"] == "b" * 64
    assert data["build"]["cmi"] == m.cmi
    assert data["audit"]["manifestDigest"] == m.digest()


def test_manifest_rejects_tool_without_capability():
    try:
        build_manifest(
            did="did:wba:test:tp:ap", phc_digest="a" * 64, issuer="tp", af_ref="b" * 64,
            modules=[("summarize", "1.0.0", "aa" * 32)], capabilities=[],
            tools=[ToolDeclaration("bad", "missing", "bad")],
        )
    except ManifestError:
        return
    raise AssertionError("未声明能力的工具必须被拒绝")


def test_gateway_requires_confirmation_and_audits():
    m = _manifest()
    m.tools = [ToolDeclaration("calendar.create", "summarize", "test", "high", True, ("create",))]
    gateway = ToolGateway(m, handlers={"calendar.create": lambda args: {"ok": True}})
    pending = gateway.request("calendar.create", "create", {"title": "demo"})
    assert pending["status"] == "confirmation_required"
    done = gateway.confirm(pending["requestId"])
    assert done["status"] == "completed"
    assert len(gateway.audit) == 1 and gateway.audit[0].user_confirmed is True


def test_gateway_rejects_unknown_tool_and_bad_operation():
    gateway = ToolGateway(_manifest(), handlers={})
    try:
        gateway.request("unknown", "run", {})
    except GatewayError:
        pass
    else:
        raise AssertionError("未知工具必须拒绝")
    m = _manifest()
    m.tools = [ToolDeclaration("summarize.run", "summarize", "摘要", allowed_operations=("run",))]
    gateway = ToolGateway(m, handlers={"summarize.run": lambda args: {}})
    try:
        gateway.request("summarize.run", "delete", {})
    except GatewayError:
        return
    raise AssertionError("未声明操作必须拒绝")


def test_local_conversation_routes_deterministically():
    m = _manifest()
    gateway = ToolGateway(m, handlers={"summarize.run": lambda args: {"summary": args["text"]}})
    chat = LocalConversation(gateway)
    result = chat.send("摘要 hello")
    assert result["status"] == "completed"
    assert result["result"]["summary"] == "hello"
