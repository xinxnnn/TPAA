"""AG2 personal-agent chat UI server.

The browser talks to this local service. DeepSeek credentials stay server-side.
AG2 owns the model/tool loop; every executable tool delegates to ToolGateway.

Run:
    $env:DEEPSEEK_API_KEY = "..."
    python demos/personal_agent/run_ag2_chat.py
    Open http://127.0.0.1:8765
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

from ag2 import Agent, tool  # noqa: E402
from ag2.config import OpenAICompletionsConfig  # noqa: E402
from tpaa_runtime.manifest import Capability, ToolDeclaration, build_manifest  # noqa: E402
from tpaa_runtime.sandbox import GatewayError, ToolGateway  # noqa: E402


HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AG2 Personal Agent</title><style>
:root{font-family:Inter,system-ui,sans-serif;color:#e8efee;background:#172321}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:#172321}body{overflow:auto}.app{min-height:100vh;display:grid;grid-template-columns:250px minmax(0,1fr) 285px;overflow:visible}.side{background:#1e2d2b;border-right:1px solid #35504a;padding:26px 18px;min-height:100vh}.brand{display:flex;gap:11px;align-items:center;margin-bottom:35px}.mark{background:#bce9db;color:#155b51;border-radius:9px;width:34px;height:34px;display:grid;place-items:center;font-weight:800}.brand strong{display:block}.brand small{color:#91aaa4;font-size:11px}.label{font-size:10px;letter-spacing:1.3px;color:#88aaa1;font-weight:700;margin:20px 8px 10px}.side button{display:block;width:100%;border:0;background:transparent;color:#b6cac4;text-align:left;padding:11px 10px;border-radius:6px;margin:3px 0;cursor:pointer}.side button.active,.side button:hover{background:#2d4842;color:#fff}.status{border-top:1px solid #38504b;margin-top:30px;padding-top:15px;color:#98b0aa;font-size:11px;line-height:1.8}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#3fc29e;margin-right:6px}.chat{min-height:100vh;display:flex;flex-direction:column;background:#f4f7f5;color:#1d2927}.chat-head{height:70px;flex:none;background:#fff;border-bottom:1px solid #dfe8e4;padding:15px 29px;display:flex;justify-content:space-between;align-items:center}.chat-head h1{font-size:16px;margin:0}.chat-head small{display:block;color:#77908a;font-size:11px;margin-top:4px}.pill{border:1px solid #b9ded3;color:#187665;padding:6px 10px;border-radius:20px;font-size:10px;background:#f0faf6}.messages{flex:1;min-height:0;overflow-y:auto;padding:28px max(24px,calc((100% - 750px)/2));display:flex;flex-direction:column;gap:18px}.bubble{max-width:80%;padding:13px 15px;border-radius:10px;font-size:13px;line-height:1.65;white-space:pre-wrap}.user{align-self:flex-end;background:#0a806f;color:#fff;border-bottom-right-radius:2px}.agent{align-self:flex-start;background:#fff;border:1px solid #dfe8e4;color:#263634;border-bottom-left-radius:2px}.tool{font-size:11px;border-left:3px solid #d19850;background:#fff8ec;padding:9px 11px;color:#6b583c}.composer{flex:none;background:#fff;border-top:1px solid #dfe8e4;padding:16px max(24px,calc((100% - 750px)/2));display:flex;gap:10px}.composer textarea{flex:1;resize:none;border:1px solid #ccd9d5;border-radius:7px;padding:11px;font:13px inherit;min-height:42px}.composer button{background:#0a806f;color:#fff;border:0;border-radius:7px;padding:0 18px;font-weight:600;cursor:pointer}.inspector{background:#1e2d2b;padding:25px 18px;color:#c1d1cc;min-height:100vh;overflow-y:auto}.inspector h2{font-size:13px;color:#fff;margin:0 0 20px}.card{border:1px solid #38504b;background:#243833;border-radius:7px;padding:12px;margin-bottom:12px}.card label{display:block;color:#88aaa1;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}.card code{font-size:10px;word-break:break-all;color:#c7e5db}.tool-row{padding:9px 0;border-bottom:1px solid #38504b;font-size:11px}.tool-row:last-child{border:0}.risk{float:right;color:#dcb16f;font-size:9px}.confirm{background:#fff5e4;border:1px solid #e2bf88;color:#654e2f;padding:12px;margin:10px 0;border-radius:6px;font-size:11px}.confirm button{margin-top:8px;border:0;background:#b77732;color:#fff;padding:7px 10px;border-radius:4px;cursor:pointer}@media(max-width:900px){.app{grid-template-columns:1fr}.side,.inspector{display:none}.chat-head{padding:13px 16px}.messages,.composer{padding-left:16px;padding-right:16px}}
</style></head><body><div class="app"><aside class="side"><div class="brand"><span class="mark">A</span><span><strong>AG2 / Personal Agent</strong><small>tpaa_v1 identity runtime</small></span></div><div class="label">WORKSPACE</div><button class="active">对话</button><button>能力清单</button><button>工具与权限</button><button>记忆策略</button><button>运行审计</button><div class="status"><span class="dot"></span>Runtime ready<br>PHC verified · v3<br>Manifest preflight passed<br>Secret refs protected</div></aside><main class="chat"><header class="chat-head"><div><h1>个人智能体 / AG2 Demo</h1><small>本地对话桌面 · DeepSeek provider · Tool Gateway enforced</small></div><span class="pill">● CONNECTED</span></header><div id="messages" class="messages"></div><form id="form" class="composer"><textarea id="input" placeholder="和你的智能体对话…" rows="1"></textarea><button>发送</button></form></main><aside class="inspector"><h2>Agent Identity</h2><div class="card"><label>DID</label><code>did:wba:demo-ag2:tp.example:ap.example</code></div><div class="card"><label>PHC binding</label><code>tpaa_v1 / credentialDigest<br>443d4e1b…307515<br>status v0</code></div><div class="card"><label>Manifest / CMI</label><code id="digest">loading…</code></div><h2>Enabled Tools</h2><div class="card"><div class="tool-row">summarize.run <span class="risk">LOW</span></div><div class="tool-row">knowledge.search <span class="risk">MEDIUM</span></div><div class="tool-row">calendar.create <span class="risk">CONFIRM</span></div></div><div id="confirmation"></div></aside></div><script>
const messages=document.querySelector('#messages'),input=document.querySelector('#input'),form=document.querySelector('#form'),confirmation=document.querySelector('#confirmation');let history=[];function add(text,kind){const d=document.createElement('div');d.className='bubble '+kind;d.textContent=text;messages.append(d);messages.scrollTop=messages.scrollHeight}function addTool(text){const d=document.createElement('div');d.className='tool';d.textContent='Tool Gateway · '+text;messages.append(d)}async function send(text){add(text,'user');const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,history})});const j=await r.json();if(j.tool)addTool(j.tool);if(j.confirmation){confirmation.innerHTML='<div class="confirm">高风险工具调用需要确认：'+j.confirmation.operation+'<br><button id="confirm">确认执行</button></div>';document.querySelector('#confirm').onclick=async()=>{const x=await fetch('/api/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:j.confirmation.requestId})}).then(r=>r.json());addTool('用户确认 · '+JSON.stringify(x.result));confirmation.innerHTML='';}}add(j.message,'agent');history.push({user:text,assistant:j.message})}form.onsubmit=e=>{e.preventDefault();const t=input.value.trim();if(t){input.value='';send(t)}};add('你好，我是绑定到 tpaa_v1 PHC 的 AG2 个人智能体。你可以让我摘要、检索本地知识，或请求一个需要确认的日历操作。','agent');
</script></body></html>"""


def _build_gateway() -> ToolGateway:
    modules = [("summarize", "1.0.0", "aa" * 32), ("knowledge", "1.0.0", "bb" * 32), ("calendar", "1.0.0", "cc" * 32)]
    capabilities = [
        Capability("summarize", "1.0.0", "内容摘要"),
        Capability("knowledge", "1.0.0", "本地检索", risk_level="medium"),
        Capability("calendar", "1.0.0", "日历操作", risk_level="high", requires_confirmation=True, network_access=True),
    ]
    tools = [
        ToolDeclaration("summarize.run", "summarize", "摘要文本", allowed_operations=("run",)),
        ToolDeclaration("knowledge.search", "knowledge", "本地检索", "medium", allowed_operations=("search",)),
        ToolDeclaration("calendar.create", "calendar", "创建日历", "high", True, ("create_event",)),
    ]
    manifest = build_manifest(
        did="did:wba:demo-ag2:tp.example:ap.example", phc_digest="443d4e1b65c7fb09e921b5b769fb3242f02638c8e6861433e3b3fe8c83307515",
        issuer="tp-demo-public-key", af_ref="demo-af-ref", modules=modules, capabilities=capabilities, tools=tools,
        connectors=[{"id": "calendar", "auth": {"mode": "secret_ref", "secretRef": "user.calendar.default"}}],
    )
    return ToolGateway(manifest, handlers={
        "summarize.run": lambda a: {"summary": a.get("text", "")[:80]},
        "knowledge.search": lambda a: {"hits": ["TPAA protocol map", "AG2 manifest"]},
        "calendar.create": lambda a: {"eventId": "demo-001", **a},
    })


def _make_agent(gateway: ToolGateway, api_key: str, model: str, base_url: str) -> Agent:
    def run_tool(tool_id: str, operation: str, arguments: dict) -> str:
        result = gateway.request(tool_id, operation, arguments)
        if result["status"] == "confirmation_required":
            return json.dumps({"status": "confirmation_required", **result}, ensure_ascii=False)
        return json.dumps(result, ensure_ascii=False)

    @tool(name="summarize_run", description="摘要用户提供的文本")
    def summarize_run(text: str) -> str:
        """Summarize input text through the TPAA gateway."""
        return run_tool("summarize.run", "run", {"text": text})

    @tool(name="knowledge_search", description="在本地知识索引中检索")
    def knowledge_search(query: str) -> str:
        """Search the local index through the TPAA gateway."""
        return run_tool("knowledge.search", "search", {"query": query})

    @tool(name="calendar_create", description="创建日历事件；执行前必须获得用户确认")
    def calendar_create(title: str) -> str:
        """Request calendar creation through the confirmation-enforcing TPAA gateway."""
        return run_tool("calendar.create", "create_event", {"title": title})

    config = OpenAICompletionsConfig(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=0.2,
    )
    return Agent(
        name="tpaa_personal_agent",
        prompt="You are a TPAA personal agent. Use only the provided tools for actions. Explain tool results clearly. If a tool reports confirmation_required, do not claim the action is complete; ask the user to confirm.",
        config=config,
        tools=[summarize_run, knowledge_search, calendar_create],
    )


class ChatHandler(BaseHTTPRequestHandler):
    gateway: ToolGateway | None = None
    agent: Agent | None = None
    loop: asyncio.AbstractEventLoop | None = None

    def _json(self, data: dict, status: int = 200):
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/":
            raw = HTML.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        else: self.send_error(404)

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(size) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "请求 JSON 无效"}, 400); return
        if self.path == "/api/chat":
            self._chat(data.get("text", "")); return
        if self.path == "/api/confirm":
            try: self._json(self.gateway.confirm(data["requestId"]))
            except (GatewayError, KeyError) as exc: self._json({"error": str(exc)}, 400)
            return
        self.send_error(404)

    def _chat(self, text: str):
        if not isinstance(text, str) or not text.strip():
            self._json({"message": "请输入消息。"}, 400); return
        try:
            self.gateway.preflight()
            reply = self.loop.run_until_complete(self.agent.ask(text))
            content = reply.body or ""
            pending = next((x for x in self.gateway.pending.values() if x.get("toolId") == "calendar.create"), None)
            if pending:
                request_id = next(k for k, v in self.gateway.pending.items() if v is pending)
                self._json({"message": content or "该日历操作等待你的确认。", "confirmation": {"requestId": request_id, "operation": pending["operation"]}, "tool": "calendar.create · confirmation required"})
                return
            self._json({"message": content, "tool": "AG2 Agent · Tool Gateway active"})
        except Exception as exc:
            self._json({"message": str(exc), "tool": "AG2/provider error"}, 400)

    def log_message(self, *_): pass


def main():
    api_key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not api_key:
        raise SystemExit("缺少 DEEPSEEK_API_KEY；请在启动 AG2 服务前设置环境变量")
    gateway = _build_gateway()
    config_model = (os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat").strip()
    base_url = (os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com/v1").rstrip("/")
    loop = asyncio.new_event_loop()
    ChatHandler.gateway = gateway
    ChatHandler.agent = _make_agent(gateway, api_key, config_model, base_url)
    ChatHandler.loop = loop
    print(f"AG2 {Agent.__module__}.Agent · DeepSeek model={config_model} · http://127.0.0.1:8765")
    try:
        ThreadingHTTPServer(("127.0.0.1", 8765), ChatHandler).serve_forever()
    finally:
        loop.close()


if __name__ == "__main__":
    main()
