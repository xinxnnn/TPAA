"""AG2 本地对话沙盒演示。

    python demos/personal_agent/demo_ag2_sandbox.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

from tpaa_runtime.manifest import Capability, ToolDeclaration, build_manifest  # noqa: E402
from tpaa_runtime.sandbox import LocalConversation, ToolGateway  # noqa: E402


MODULES = [
    ("summarize", "1.0.0", "aa" * 32),
    ("knowledge", "1.0.0", "bb" * 32),
    ("calendar", "1.0.0", "cc" * 32),
]


def summarize(args):
    text = args["text"].strip()
    return {"summary": text[:80] + ("…" if len(text) > 80 else ""), "inputBytes": len(text.encode())}


def search(args):
    return {"query": args["query"], "hits": ["TPAA protocol map", "AG2 local manifest"]}


def create_event(args):
    return {"eventId": "evt-demo-001", "title": args["title"], "calendar": "demo-calendar"}


def main() -> int:
    caps = [
        Capability("summarize", "1.0.0", "内容摘要", ("text",), ("summary",)),
        Capability("knowledge", "1.0.0", "本地知识检索", ("query",), ("hits",), "medium"),
        Capability("calendar", "1.0.0", "日历操作", ("title",), ("event",), "high", True, True),
    ]
    tools = [
        ToolDeclaration("summarize.run", "summarize", "摘要输入文本", allowed_operations=("run",)),
        ToolDeclaration("knowledge.search", "knowledge", "检索本地索引", "medium", False, ("search",)),
        ToolDeclaration("calendar.create", "calendar", "创建日历事件", "high", True, ("create_event",)),
    ]
    manifest = build_manifest(
        did="did:wba:demo-ag2:tp.example:ap.example",
        phc_digest=hashlib.sha256(b"demo-phc-v3").hexdigest(),
        issuer="tp-demo-public-key",
        af_ref=hashlib.sha256(b"demo-af").hexdigest(),
        modules=MODULES, capabilities=caps, tools=tools,
        connectors=[{"id": "calendar", "auth": {"mode": "secret_ref", "secretRef": "user.calendar.default"}}],
        created_at="2026-10-28T10:00:00",
    )
    gateway = ToolGateway(manifest, handlers={
        "summarize.run": summarize,
        "knowledge.search": search,
        "calendar.create": create_event,
    })
    conversation = LocalConversation(gateway)

    print("=" * 80)
    print("AG2 本地对话沙盒 / Tool Gateway Demo")
    print("=" * 80)
    print("PHC binding:", json.dumps(manifest.phc.__dict__, ensure_ascii=False))
    print("DID:", manifest.did)
    print("CMI:", manifest.cmi)
    print("Manifest digest:", manifest.digest())
    print("Build digest:", manifest.build_digest)
    print("Tools:", json.dumps([t.to_json() for t in tools], ensure_ascii=False, indent=2))

    for prompt in ("摘要 TPAA 的用户身份与 PHC 初始化流程", "检索 manifest", "创建日历 明天下午评审 PHC"):
        result = conversation.send(prompt)
        print("\nUSER:", prompt)
        print("AG2:", result["message"])
        print("TOOL STATE:", result["status"])
        if result["status"] == "confirmation_required":
            print("CONFIRM REQUEST:", result["requestId"])
            confirmed = conversation.confirm(result["requestId"])
            print("AFTER CONFIRM:", confirmed)

    print("\nAUDIT:")
    for event in gateway.audit:
        print(json.dumps(event.__dict__, ensure_ascii=False))
    print("\n沙盒演示完成：LLM 未接入，所有工具调用仍经过 manifest / policy / confirmation / audit。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
