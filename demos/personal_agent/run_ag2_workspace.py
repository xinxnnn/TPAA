"""Local AG2 capability workbench.

Run from the repository root:
    python demos/personal_agent/run_ag2_workspace.py

Open http://127.0.0.1:8766. Configure an OpenAI-compatible API in the page.
The API key is held in process memory only and is never returned to the browser.
"""
from __future__ import annotations

import ast
import asyncio
import json
import operator
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

from ag2 import Agent, tool
from ag2.config import OpenAICompletionsConfig
from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent
from ag2.testing import TestConfig
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

WORKSPACE = ROOT / "demo_workspace"
KNOWLEDGE = [
    {"title": "运行时设计原则", "text": "Agent 负责规划，工具负责执行；所有副作用操作需要确认。"},
    {"title": "能力边界", "text": "AG2 编排已注册工具，不原生控制 Windows 桌面。桌面操作需要独立 worker。"},
    {"title": "任务与审计", "text": "工具调用要记录输入、结果、状态和关联会话，便于回放与审计。"},
]
CAPABILITY_CATALOG = [
    {"id": "web.search", "group": "信息获取", "risk": "低", "description": "网页检索", "source": "AG2 搜索集成 + 外部搜索服务", "state": "needs_setup", "enabled": False, "note": "需要 ddgs/Tavily 等依赖或 API；当前未连接真实搜索服务。"},
    {"id": "web.fetch", "group": "信息获取", "risk": "低", "description": "抓取公开网页内容", "source": "HTTP Connector", "state": "needs_setup", "enabled": False, "note": "尚未配置抓取器和域名策略。"},
    {"id": "file.search", "group": "信息获取", "risk": "低", "description": "文档 / 向量检索", "source": "AG2 File Search / Knowledge + Provider 或存储", "state": "needs_setup", "enabled": False, "note": "需要支持的 Provider、文档库和访问权限。"},
    {"id": "knowledge.search", "group": "信息获取", "risk": "低", "description": "检索 Demo 本地知识条目", "source": "本地 Python 工具", "state": "ready", "enabled": True, "note": "仅检索内置演示数据，不是用户知识库。"},
    {"id": "maps.query", "group": "信息获取", "risk": "低", "description": "地点与地图检索", "source": "AG2 Google Maps Tool（Gemini 支持）", "state": "needs_setup", "enabled": False, "note": "需要 Gemini Provider 和地图 API 权限。"},
    {"id": "document.write", "group": "内容生成", "risk": "中", "description": "生成文档文件", "source": "文档生成 Connector", "state": "needs_setup", "enabled": False, "note": "当前不生成 docx / pdf。"},
    {"id": "image.generate", "group": "内容生成", "risk": "中", "description": "图像生成", "source": "AG2 Image Generation Tool（OpenAI Responses）", "state": "needs_setup", "enabled": False, "note": "Provider 和 API 类型受限，当前未配置。"},
    {"id": "code.generate", "group": "内容生成", "risk": "低", "description": "生成代码文本", "source": "Agent 文本输出", "state": "ready", "enabled": True, "note": "模型可输出代码文本；未接入代码校验器。"},
    {"id": "report.compose", "group": "内容生成", "risk": "低", "description": "生成结构化报告草稿", "source": "AG2 自定义工具 + Agent", "state": "ready", "enabled": True, "note": "草稿保存在本进程内存。"},
    {"id": "presentation.create", "group": "内容生成", "risk": "中", "description": "生成演示文稿", "source": "文档生成 Connector / AG2 Skill", "state": "needs_setup", "enabled": False, "note": "未接入 pptx 生成器。"},
    {"id": "code.execute", "group": "执行操作", "risk": "高", "description": "隔离环境执行代码", "source": "AG2 CodeExecution Tool + Sandbox", "state": "needs_setup", "enabled": False, "note": "AG2 有代码执行工具接口；当前没有配置隔离沙盒。"},
    {"id": "file.write", "group": "执行操作", "risk": "高 · 确认", "description": "写入 Demo 工作区", "source": "受限文件 Connector + 确认队列", "state": "ready", "enabled": True, "note": "只写 demo_workspace；目标已存在时拒绝覆盖。"},
    {"id": "email.send", "group": "执行操作", "risk": "高 · 确认", "description": "发送邮件", "source": "邮件 API / MCP Connector", "state": "needs_setup", "enabled": False, "note": "未配置邮件服务和收件人策略。"},
    {"id": "calendar.create", "group": "执行操作", "risk": "高 · 确认", "description": "创建日历事件", "source": "Calendar API / MCP Connector", "state": "needs_setup", "enabled": False, "note": "未配置日历服务。"},
    {"id": "task.create", "group": "执行操作", "risk": "中", "description": "创建并跟踪任务", "source": "TPAA Task Service", "state": "planned", "enabled": False, "note": "当前没有持久化任务引擎。"},
    {"id": "agent.ask", "group": "协同通信", "risk": "中高", "description": "请求另一个 Agent 协作", "source": "AG2 Agent / A2A / MCP + 信任策略", "state": "needs_setup", "enabled": False, "note": "未接入远端目录和通信。"},
    {"id": "human.approve", "group": "协同通信", "risk": "审批", "description": "人工确认副作用操作", "source": "本地工作台确认队列", "state": "ready", "enabled": True, "note": "报告写入前提供确认/取消。"},
    {"id": "team.notify", "group": "协同通信", "risk": "高 · 确认", "description": "通知团队频道", "source": "Chat / Webhook Connector", "state": "needs_setup", "enabled": False, "note": "未配置团队消息服务。"},
    {"id": "desktop.control", "group": "桌面自动化", "risk": "高 · 确认", "description": "操作 Windows 桌面", "source": "外部 Desktop Worker（非 AG2 内置）", "state": "unsupported", "enabled": False, "note": "AG2 本身不控制桌面；需单独实现 Worker。"},
    {"id": "domain.custom", "group": "专业领域", "risk": "按工具策略", "description": "研发 / 财务 / 法务 / 医疗工具", "source": "领域 API / MCP / 自定义工具", "state": "needs_setup", "enabled": False, "note": "逐项接入；医疗用途需额外资质与合规审查。"},
    {"id": "calculator.evaluate", "group": "效率工具", "risk": "低", "description": "受限数学表达式计算", "source": "本地安全计算工具", "state": "ready", "enabled": True, "note": "只解析数字和算术运算，不执行 Python。"},
    {"id": "workspace.list", "group": "文件", "risk": "低", "description": "列出 Demo 工作区文件", "source": "本地受限文件 Connector", "state": "ready", "enabled": True, "note": "仅访问 demo_workspace。"},
    {"id": "workspace.read", "group": "文件", "risk": "中", "description": "读取 Demo 工作区文本", "source": "本地受限文件 Connector", "state": "ready", "enabled": True, "note": "仅访问 demo_workspace。"},
]
CAPABILITY_BY_ID = {item["id"]: item for item in CAPABILITY_CATALOG}
CAPABILITIES = CAPABILITY_CATALOG
TOOL_CAPABILITY_IDS = {
    "knowledge_search": "knowledge.search", "calculator_evaluate": "calculator.evaluate",
    "workspace_list": "workspace.list", "workspace_read": "workspace.read",
    "report_draft": "report.compose", "report_write": "file.write",
}
DRAFTS: dict[str, dict[str, str]] = {}
PENDING: dict[str, dict[str, str]] = {}
APPROVALS: dict[str, str] = {}
SESSIONS: dict[str, "Session"] = {}



def calculate(expression: str) -> float | int:
    ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
           ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
           ast.USub: operator.neg, ast.UAdd: operator.pos}

    def visit(node):
        if isinstance(node, ast.Expression): return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)): return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in ops: return ops[type(node.op)](visit(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in ops:
            right = visit(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 10: raise ValueError("指数超限")
            value = ops[type(node.op)](visit(node.left), right)
            if abs(value) > 10**12: raise ValueError("结果超限")
            return value
        raise ValueError("只允许数字、括号和 + - * / % ** 运算")
    return visit(ast.parse(expression, mode="eval"))


def safe_path(name: str) -> Path:
    base = WORKSPACE.resolve()
    path = (base / name).resolve()
    if path != base and base not in path.parents:
        raise ValueError("仅允许访问 demo_workspace 内的文件")
    return path


@tool(name="knowledge_search", description="检索本地知识库并返回匹配条目")
def knowledge_search(query: str) -> str:
    words = [w.casefold() for w in query.split() if w]
    hits = [x for x in KNOWLEDGE if any(w in (x["title"] + x["text"]).casefold() for w in words)]
    return json.dumps({"query": query, "results": hits}, ensure_ascii=False)


@tool(name="calculator_evaluate", description="计算安全数学表达式，例如 (12+8)*3")
def calculator_evaluate(expression: str) -> str:
    try: return json.dumps({"expression": expression, "result": calculate(expression)}, ensure_ascii=False)
    except (SyntaxError, ValueError, ZeroDivisionError) as e: return json.dumps({"error": str(e)}, ensure_ascii=False)


@tool(name="workspace_list", description="列出 Demo 工作区内的文件")
def workspace_list() -> str:
    WORKSPACE.mkdir(exist_ok=True)
    return json.dumps({"files": sorted(str(p.relative_to(WORKSPACE)) for p in WORKSPACE.rglob("*") if p.is_file())}, ensure_ascii=False)


@tool(name="workspace_read", description="读取 Demo 工作区内的 UTF-8 文本文件")
def workspace_read(name: str) -> str:
    try: return json.dumps({"name": name, "content": safe_path(name).read_text(encoding="utf-8")}, ensure_ascii=False)
    except (OSError, ValueError) as e: return json.dumps({"error": str(e)}, ensure_ascii=False)


@tool(name="report_draft", description="创建一份内存中的报告草稿，不会写文件")
def report_draft(title: str, body: str) -> str:
    draft_id = "draft-" + uuid.uuid4().hex[:8]
    DRAFTS[draft_id] = {"title": title, "body": body}
    return json.dumps({"status": "drafted", "draftId": draft_id, "title": title}, ensure_ascii=False)


@tool(name="report_write", description="请求把报告草稿写入工作区；此工具只登记确认请求，不直接写文件")
def report_write(draft_id: str, filename: str) -> str:
    if draft_id not in DRAFTS: return json.dumps({"status": "denied", "reason": "草稿不存在"}, ensure_ascii=False)
    if draft_id in APPROVALS:
        if APPROVALS[draft_id] != filename: return json.dumps({"status": "denied", "reason": "确认的目标路径不匹配"}, ensure_ascii=False)
        return json.dumps({"status": "confirmation_required", "draftId": draft_id, "filename": filename}, ensure_ascii=False)
    request_id = "confirm-" + uuid.uuid4().hex[:8]
    PENDING[request_id] = {"draftId": draft_id, "filename": filename, "session_id": ""}
    return json.dumps({"status": "confirmation_required", "requestId": request_id,
                       "draftId": draft_id, "filename": filename}, ensure_ascii=False)


TOOLS = [knowledge_search, calculator_evaluate, workspace_list, workspace_read, report_draft, report_write]
TOOL_CAPABILITIES = ["knowledge.search", "calculator.evaluate", "workspace.list", "workspace.read",
                     "report.compose", "file.write"]
ENABLED_CAPABILITIES = {x for x in TOOL_CAPABILITIES if CAPABILITY_BY_ID[x]["enabled"]}
SYSTEM = ("你是一个个人工作助理。通过已提供工具检索、计算、查看工作区文件、撰写报告。"
          "不得编造工具结果。写入文件必须调用 report_write 并等待用户在界面确认；"
          "工具返回 confirmation_required 时，明确说明尚未写入。不要尝试桌面控制。")


@dataclass
class Session:
    agent: Agent
    history: list[dict[str, str]] = field(default_factory=list)
    busy: bool = False


class Configure(BaseModel):
    provider: str = "deepseek"
    api_key: str
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com/v1"


class ChatRequest(BaseModel):
    session_id: str | None = None
    text: str


class ApproveRequest(BaseModel):
    request_id: str
    approved: bool


app = FastAPI(title="AG2 Capability Workbench")
CONFIG: dict[str, str] | None = None


def make_agent(config: OpenAICompletionsConfig) -> Agent:
    tools = [fn for fn, capability_id in zip(TOOLS, TOOL_CAPABILITIES) if capability_id in ENABLED_CAPABILITIES]
    agent = Agent("personal_capability_agent", SYSTEM, config=config, tools=tools)
    agent.enabled_capabilities = sorted(ENABLED_CAPABILITIES)
    return agent


@app.get("/", response_class=HTMLResponse)
def index():
    catalog_json = json.dumps(CAPABILITY_CATALOG, ensure_ascii=False).replace("</", "<\\/")
    return HTML.replace("__CAPABILITY_CATALOG__", catalog_json)


@app.get("/api/capabilities")
def capabilities():
    return {"capabilities": CAPABILITIES, "ag2": "1.2.2", "desktop_control": False,
            "enabled": sorted(ENABLED_CAPABILITIES)}


class CapabilityToggle(BaseModel):
    id: str
    enabled: bool


@app.post("/api/capabilities/toggle")
def toggle_capability(body: CapabilityToggle):
    item = CAPABILITY_BY_ID.get(body.id)
    if item is None:
        raise HTTPException(404, "未知能力")
    if item["state"] != "ready":
        raise HTTPException(409, f"能力当前不可运行：{item['note']}")
    if body.id not in TOOL_CAPABILITY_IDS.values():
        raise HTTPException(409, "该能力当前没有绑定到 AG2 工具")
    item["enabled"] = body.enabled
    if body.enabled:
        ENABLED_CAPABILITIES.add(body.id)
    else:
        ENABLED_CAPABILITIES.discard(body.id)
    return {"id": body.id, "enabled": body.id in ENABLED_CAPABILITIES,
            "applies": "new_sessions"}



@app.post("/api/configure")
def configure(body: Configure):
    global CONFIG
    if not body.api_key.strip(): raise HTTPException(400, "API Key 不能为空")
    if not body.base_url.startswith(("https://", "http://")): raise HTTPException(400, "Base URL 需要是 HTTP(S) 地址")
    CONFIG = {"api_key": body.api_key.strip(), "model": body.model.strip(), "base_url": body.base_url.rstrip("/")}
    return {"configured": True, "provider": body.provider, "model": body.model, "key_saved": False}


@app.post("/api/session")
def new_session():
    if CONFIG is None: raise HTTPException(400, "请先配置模型 API")
    config = OpenAICompletionsConfig(model=CONFIG["model"], api_key=CONFIG["api_key"],
                                     base_url=CONFIG["base_url"], temperature=0.2)
    sid = uuid.uuid4().hex[:12]
    SESSIONS[sid] = Session(make_agent(config))
    return {"session_id": sid, "enabled_tools": sorted(SESSIONS[sid].agent.enabled_capabilities)}


async def transcript(reply) -> tuple[str, list[dict[str, Any]]]:
    events = []
    for ev in await reply.history.get_events():
        if isinstance(ev, ToolCallEvent):
            events.append({"kind": "call", "tool": ev.name, "arguments": ev.arguments})
        elif isinstance(ev, ToolResultEvent):
            parts = ev.result.parts
            value = "".join(str(p.content) for p in parts)
            parsed = None
            try: parsed = json.loads(value)
            except (ValueError, TypeError): pass
            events.append({"kind": "result", "tool": ev.name, "result": parsed if parsed is not None else value})
        elif isinstance(ev, ToolErrorEvent): events.append({"kind": "error", "tool": ev.name, "error": str(ev.error)})
    return reply.body or "", events


@app.post("/api/chat")
async def chat(body: ChatRequest):
    if CONFIG is None: raise HTTPException(400, "请先配置模型 API")
    text = body.text.strip()
    if not text: raise HTTPException(400, "请输入任务")
    session = SESSIONS.get(body.session_id or "")
    if session is None:
        result = new_session()
        session = SESSIONS[result["session_id"]]
        sid = result["session_id"]
    else: sid = body.session_id
    if session.busy: raise HTTPException(409, "该会话正在处理请求")
    session.busy = True
    try:
        reply = await session.agent.ask(text)
        answer, events = await transcript(reply)
        for pending in PENDING.values():
            if not pending.get("session_id"):
                pending["session_id"] = sid
        session.history.extend([{"role": "user", "text": text}, {"role": "assistant", "text": answer}])
        return {"session_id": sid, "answer": answer, "events": events,
                "enabled_capabilities": session.agent.enabled_capabilities,
                "pending": [{"request_id": rid, **req} for rid, req in PENDING.items() if req.get("session_id") == sid]}
    except Exception as e:
        raise HTTPException(502, f"AG2 / Provider error: {type(e).__name__}: {e}") from e
    finally: session.busy = False


@app.post("/api/approve")
def approve(body: ApproveRequest):
    req = PENDING.pop(body.request_id, None)
    if req is None: raise HTTPException(404, "确认请求不存在或已处理")
    if not body.approved: return {"status": "cancelled", "request_id": body.request_id}
    try:
        draft = DRAFTS[req["draftId"]]
        path = safe_path(req["filename"])
        if path.exists(): raise HTTPException(409, "目标文件已存在，本 Demo 不覆盖文件")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {draft['title']}\n\n{draft['body']}\n", encoding="utf-8")
    except (OSError, ValueError) as e: raise HTTPException(400, str(e)) from e
    return {"status": "written", "path": str(path.relative_to(WORKSPACE))}


@app.post("/api/scripted-demo")
async def scripted_demo():
    """Deterministic no-API guided run to preview actual AG2 tool execution."""
    config = TestConfig(
        ToolCallEvent(name="knowledge_search", arguments=json.dumps({"query": "AG2 桌面能力边界"}, ensure_ascii=False)),
        ToolCallEvent(name="calculator_evaluate", arguments='{"expression":"(12+8)*3"}'),
        ToolCallEvent(name="report_draft", arguments=json.dumps({"title": "能力演示报告", "body": "AG2 工具循环运行成功。"}, ensure_ascii=False)),
        ToolCallEvent(name="report_write", arguments='{"draft_id":"draft-demo","filename":"reports/demo.md"}'),
        "工具运行完成。报告写入等待确认。", raise_tool_errors=False)
    draft_id = "draft-demo"
    DRAFTS[draft_id] = {"title": "能力演示报告", "body": "AG2 工具循环运行成功。"}
    agent = Agent("scripted_demo", SYSTEM, config=config,
                  tools=[fn for fn, capability_id in zip(TOOLS, TOOL_CAPABILITIES)
                         if capability_id in ENABLED_CAPABILITIES])
    agent.enabled_capabilities = sorted(ENABLED_CAPABILITIES)
    reply = await agent.ask("请查找 AG2 的能力边界，计算 (12+8)*3，并生成报告，最后请求写入。")
    answer, events = await transcript(reply)
    pending = next((rid for rid, value in PENDING.items() if value.get("draftId") == draft_id), None)
    return {"answer": answer, "events": events, "pending": [{"request_id": pending, **PENDING[pending]}] if pending else [],
            "enabled_capabilities": agent.enabled_capabilities, "scripted": True}


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AG2 能力工作台</title>
<style>
:root{color-scheme:light;--ink:#1e2a29;--muted:#6c7a77;--line:#dde5e1;--paper:#fff;--bg:#f3f6f4;--teal:#087f73;--teal-soft:#e4f2ee;--amber:#a5631b;--amber-soft:#fbf1df;--red:#a13f38;--red-soft:#f9e9e7;--green:#28734d}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 Inter,"Microsoft YaHei",sans-serif}button,input,select,textarea{font:inherit}button{cursor:pointer}.layout{min-height:100vh;display:grid;grid-template-columns:230px minmax(400px,1fr) 310px;grid-template-rows:58px minmax(0,1fr)}header{grid-column:1/4;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 20px}.brand{font-weight:700}.brand small{display:block;color:var(--muted);font-size:11px;font-weight:400}.status{font-size:12px;color:var(--muted)}.status i{display:inline-block;width:8px;height:8px;border-radius:50%;background:#aaa;margin-right:6px}.status.ready i{background:#36a269}.side{background:#fff;border-right:1px solid var(--line);padding:18px 12px}.label{font-size:10px;color:#83908c;text-transform:uppercase;margin:2px 8px 9px}.nav{padding:8px 9px;border-radius:4px;color:#52615c;font-size:13px}.nav.active{background:var(--teal-soft);color:#075f56;font-weight:600}.cap-count{float:right;font-size:11px;color:#87928f}.side-footer{position:sticky;top:90vh;border-top:1px solid var(--line);margin-top:26px;padding:12px 8px;color:var(--muted);font-size:11px}.work{display:flex;flex-direction:column;min-height:calc(100vh - 58px)}.work-head{padding:18px 22px 13px;background:#fff;border-bottom:1px solid var(--line)}h1{font-size:18px;margin:0 0 3px}.sub{font-size:12px;color:var(--muted)}.banner{margin:12px 0 0;padding:9px 11px;background:#f1f5f3;color:#52615c;border-left:3px solid #91a69d;font-size:12px}.banner.warn{background:var(--amber-soft);border-color:#c9822b;color:#74501f}.messages{flex:1;overflow:auto;padding:20px max(16px,calc((100% - 760px)/2));display:flex;flex-direction:column;gap:13px}.msg{max-width:88%;padding:11px 13px;border:1px solid var(--line);background:#fff;border-radius:5px;white-space:pre-wrap}.msg.user{align-self:flex-end;background:#e3f2ec;border-color:#d3e8dc}.msg.agent{align-self:flex-start}.msg-label{font-size:10px;color:var(--muted);margin-bottom:5px}.trace{align-self:flex-start;width:min(88%,680px);border:1px solid var(--line);background:#fafcfb;border-radius:4px;overflow:hidden;font-size:12px}.trace-head{padding:8px 10px;background:#f4f7f5;border-bottom:1px solid var(--line);font-weight:600}.trace-row{padding:8px 10px;border-bottom:1px solid #edf1ef}.trace-row:last-child{border:0}.trace-row b{color:var(--teal)}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:5px 0 0;font:11px/1.5 ui-monospace,Consolas,monospace;color:#51615b}.confirm{align-self:flex-start;width:min(88%,680px);padding:12px;border:1px solid #e4c38f;background:var(--amber-soft);border-radius:4px;font-size:12px}.confirm-actions{display:flex;gap:7px;margin-top:10px}.button{border:1px solid var(--line);background:#fff;color:#34413d;border-radius:4px;padding:7px 10px;font-size:12px}.button.primary{background:var(--teal);border-color:var(--teal);color:#fff}.button.danger{color:var(--red)}.composer{padding:12px 18px;background:#fff;border-top:1px solid var(--line)}.compose-inner{max-width:760px;margin:auto;display:flex;gap:8px}.compose-inner textarea{flex:1;resize:vertical;min-height:48px;max-height:140px;border:1px solid #cad6d0;border-radius:4px;padding:10px}.right{background:#fff;border-left:1px solid var(--line);padding:16px;overflow:auto}.panel{margin-bottom:20px}.panel h2{font-size:12px;margin:0 0 10px}.field{display:grid;gap:5px;margin-bottom:9px}.field label{font-size:11px;color:var(--muted)}input,select{width:100%;height:33px;border:1px solid var(--line);border-radius:4px;padding:0 8px;background:#fff;font-size:12px}.row{display:flex;gap:7px}.row>*{flex:1}.cap{display:grid;grid-template-columns:18px minmax(0,1fr) auto;gap:7px;align-items:start;padding:9px 0;border-top:1px solid #edf1ef}.cap input{width:15px;height:15px;margin:1px 0 0;accent-color:var(--teal)}.cap-copy{min-width:0}.cap strong{display:block;font-size:10px;overflow-wrap:anywhere}.cap small{display:block;margin-top:3px;color:var(--muted);font-size:9px;line-height:1.35}.cap-status{font-size:9px;white-space:nowrap;color:#65716d}.cap-status.ready{color:var(--green)}.cap-status.needs_setup{color:var(--amber)}.cap-status.unsupported{color:var(--red)}.cap-group h3{font-size:10px;color:#52615c;margin:12px 0 4px}.notice{font-size:11px;color:var(--muted);line-height:1.5}.log{font-size:10px;color:var(--muted);padding:5px 0;border-top:1px solid #edf1ef;word-break:break-word}.small{font-size:10px;color:var(--muted)}.hidden{display:none}@media(max-width:1000px){.layout{grid-template-columns:190px minmax(0,1fr);grid-template-rows:56px minmax(0,1fr)}header{grid-column:1/3}.right{display:none}}@media(max-width:640px){.layout{display:flex;flex-direction:column;min-height:100dvh}header{height:52px;flex:none}.side{display:none}.work{flex:1;min-height:calc(100dvh - 52px)}.messages{padding:14px 12px}.msg,.trace,.confirm{max-width:100%;width:100%}.composer{padding:9px}.compose-inner textarea{min-width:0}}
</style></head>
<body><div class="layout"><header><div class="brand">AG2 能力工作台<small>Personal Agent · Local Demo</small></div><div id="runtime" class="status"><i></i><span>未连接模型</span></div></header>
<aside class="side"><div class="label">运行工作区</div><div class="nav active">对话运行</div><div class="nav">能力清单 <span id="count" class="cap-count">6</span></div><div class="nav">工具调用轨迹</div><div class="side-footer">AG2 Agent 编排<br>本地工具执行 · 人工审批</div></aside>
<main class="work"><div class="work-head"><h1>个人效率助手</h1><div class="sub">让 Agent 使用明确配置的工具完成任务</div><div id="notice" class="banner">先在右侧配置兼容 OpenAI Chat Completions 的模型 API。也可以运行无 API 引导演示。</div></div><section id="messages" class="messages"><div class="msg agent"><div class="msg-label">AG2 Agent</div>你好。你可以让我查本地知识、计算表达式、查看 Demo 工作区或起草报告。写文件前会先请求确认。</div></section><div class="composer"><div class="compose-inner"><textarea id="prompt" placeholder="例如：检索能力边界，计算 (12+8)*3，并起草一份报告"></textarea><button id="send" class="button primary" onclick="sendMessage()">发送</button></div></div></main>
<aside class="right"><section class="panel"><h2>模型连接</h2><div class="field"><label>Provider</label><select id="provider"><option value="deepseek">DeepSeek</option><option value="openai">OpenAI-compatible</option></select></div><div class="field"><label>API Key（仅保存在本次进程内存）</label><input id="key" type="password" autocomplete="off" placeholder="sk-…"></div><div class="row"><div class="field"><label>模型</label><input id="model" value="deepseek-chat"></div></div><div class="field"><label>Base URL</label><input id="base" value="https://api.deepseek.com/v1"></div><div class="row"><button class="button primary" onclick="configure()">连接并开始</button><button class="button" onclick="guidedDemo()">无 API 演示</button></div><p class="notice">真实模型请求会产生对应 Provider 费用。API Key 不写入磁盘，也不会返回到页面。</p></section>
<section class="panel"><h2>全部能力与状态 <span class="small">AG2 1.2.2</span></h2><div class="small">只有标为“可运行”的能力能启用；变更对新会话生效。</div><div id="catalog"></div></section><section class="panel"><h2>当前会话</h2><div id="session" class="small">尚未创建</div><div id="sessionCaps" class="small"></div></section><section class="panel"><h2>最近工具记录</h2><div id="toolLog" class="small">运行后显示</div></section></aside></div>
<script>
let sessionId=null;const $=id=>document.getElementById(id);function esc(x){return String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function status(text,ready=false){$('runtime').className='status'+(ready?' ready':'');$('runtime').innerHTML='<i></i><span>'+esc(text)+'</span>'}function addMessage(text,kind){const d=document.createElement('div');d.className='msg '+kind;d.innerHTML='<div class="msg-label">'+(kind==='user'?'你':'AG2 Agent')+'</div>'+esc(text);$('messages').append(d);$('messages').scrollTop=$('messages').scrollHeight}function addTrace(events){if(!events||!events.length)return;const box=document.createElement('div');box.className='trace';box.innerHTML='<div class="trace-head">AG2 工具调用轨迹 · '+events.length+' 项</div>'+events.map(e=>'<div class="trace-row">'+(e.kind==='call'?'<b>调用 '+esc(e.tool)+'</b><pre>'+esc(e.arguments)+'</pre>':e.kind==='error'?'<b>错误 '+esc(e.tool)+'</b><pre>'+esc(e.error)+'</pre>':'<b>返回 '+esc(e.tool)+'</b><pre>'+esc(JSON.stringify(e.result,null,2))+'</pre>')+'</div>').join('');$('messages').append(box);$('messages').scrollTop=$('messages').scrollHeight;$('toolLog').innerHTML=events.filter(e=>e.kind==='call').map(e=>'<div class="log">'+esc(e.tool)+'</div>').join('')||'无工具调用'}function addPending(list){for(const p of (list||[])){if(document.querySelector('[data-request="'+CSS.escape(p.request_id)+'"]'))continue;const d=document.createElement('div');d.className='confirm';d.dataset.request=p.request_id;d.innerHTML='<strong>需要确认的文件写入</strong><p>目标：<code>'+esc(p.filename)+'</code><br>草稿：'+esc(p.draftId)+'</p><div class="confirm-actions"><button class="button primary" onclick="approve(\''+esc(p.request_id)+'\',true,this)">确认写入</button><button class="button danger" onclick="approve(\''+esc(p.request_id)+'\',false,this)">取消</button></div>'; $('messages').append(d);$('messages').scrollTop=$('messages').scrollHeight}}
async function configure(){const body={provider:$('provider').value,api_key:$('key').value,model:$('model').value,base_url:$('base').value};if(!body.api_key){$('notice').className='banner warn';$('notice').textContent='请填写 API Key，或点击“无 API 演示”体验固定剧本。';return}try{const c=await fetch('/api/configure',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const j=await c.json();if(!c.ok)throw Error(j.detail||'配置失败');const r=await fetch('/api/session',{method:'POST'});const s=await r.json();if(!r.ok)throw Error(s.detail||'会话创建失败');sessionId=s.session_id;$('session').textContent=sessionId;$('sessionCaps').textContent='本会话工具：'+s.enabled_tools.join(', ');$('key').value='';status('模型已连接 · '+body.model,true);$('notice').className='banner';$('notice').textContent='真实模型模式已就绪。请求将发送到你配置的 Provider，并可能产生费用。'}catch(e){$('notice').className='banner warn';$('notice').textContent=e.message}}
async function sendMessage(){const text=$('prompt').value.trim();if(!text)return;$('prompt').value='';addMessage(text,'user');$('send').disabled=true;status('AG2 正在运行工具循环…');try{const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId,text})});const j=await r.json();if(!r.ok)throw Error(j.detail||'请求失败');sessionId=j.session_id;$('session').textContent=sessionId;$('sessionCaps').textContent='本会话工具：'+j.enabled_capabilities.join(', ');addTrace(j.events);addMessage(j.answer||'(模型未返回文本)','agent');addPending(j.pending);status('AG2 运行就绪',true)}catch(e){addMessage('运行失败：'+e.message,'agent');status('运行失败');$('notice').className='banner warn';$('notice').textContent=e.message}finally{$('send').disabled=false}}
async function approve(request_id,approved,button){button.disabled=true;try{const r=await fetch('/api/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id,approved})});const j=await r.json();if(!r.ok)throw Error(j.detail||'操作失败');const el=document.querySelector('[data-request="'+CSS.escape(request_id)+'"]');if(el)el.innerHTML=approved?'已确认并写入 '+esc(j.path):'已取消，未写入文件';}catch(e){button.disabled=false;alert(e.message)}}
async function guidedDemo(){status('运行固定演示剧本…');try{const r=await fetch('/api/scripted-demo',{method:'POST'});const j=await r.json();if(!r.ok)throw Error(j.detail||'运行失败');addMessage('请查找 AG2 的能力边界，计算 (12+8)*3，并生成报告，最后请求写入。','user');addTrace(j.events);addMessage(j.answer,'agent');addPending(j.pending);status('固定演示完成（非真实模型）',true);$('notice').className='banner';$('notice').textContent='这是由 AG2 TestConfig 驱动的固定剧本；不可用能力保持禁用，不会伪装成已运行。'}catch(e){status('演示失败');$('notice').className='banner warn';$('notice').textContent=e.message}}
const CATALOG=[
    {"id": "web.search", "group": "信息获取", "risk": "低", "description": "网页检索", "source": "AG2 搜索集成 + 外部搜索服务", "state": "needs_setup", "enabled": False, "note": "需要 ddgs/Tavily 等依赖或 API；当前未连接真实搜索服务。"},
    {"id": "web.fetch", "group": "信息获取", "risk": "低", "description": "抓取公开网页内容", "source": "HTTP Connector", "state": "needs_setup", "enabled": False, "note": "尚未配置抓取器和域名策略。"},
    {"id": "file.search", "group": "信息获取", "risk": "低", "description": "文档 / 向量检索", "source": "AG2 File Search / Knowledge + Provider 或存储", "state": "needs_setup", "enabled": False, "note": "需要支持的 Provider、文档库和访问权限。"},
    {"id": "knowledge.search", "group": "信息获取", "risk": "低", "description": "检索 Demo 本地知识条目", "source": "本地 Python 工具", "state": "ready", "enabled": True, "note": "仅检索内置演示数据，不是用户知识库。"},
    {"id": "maps.query", "group": "信息获取", "risk": "低", "description": "地点与地图检索", "source": "AG2 Google Maps Tool（Gemini 支持）", "state": "needs_setup", "enabled": False, "note": "需要 Gemini Provider 和地图 API 权限。"},
    {"id": "document.write", "group": "内容生成", "risk": "中", "description": "生成文档文件", "source": "文档生成 Connector", "state": "needs_setup", "enabled": False, "note": "当前不生成 docx / pdf。"},
    {"id": "image.generate", "group": "内容生成", "risk": "中", "description": "图像生成", "source": "AG2 Image Generation Tool（OpenAI Responses）", "state": "needs_setup", "enabled": False, "note": "Provider 和 API 类型受限，当前未配置。"},
    {"id": "code.generate", "group": "内容生成", "risk": "低", "description": "生成代码文本", "source": "Agent 文本输出", "state": "ready", "enabled": True, "note": "模型可输出代码文本；未接入代码校验器。"},
    {"id": "report.compose", "group": "内容生成", "risk": "低", "description": "生成结构化报告草稿", "source": "AG2 自定义工具 + Agent", "state": "ready", "enabled": True, "note": "草稿保存在本进程内存。"},
    {"id": "presentation.create", "group": "内容生成", "risk": "中", "description": "生成演示文稿", "source": "文档生成 Connector / AG2 Skill", "state": "needs_setup", "enabled": False, "note": "未接入 pptx 生成器。"},
    {"id": "code.execute", "group": "执行操作", "risk": "高", "description": "隔离环境执行代码", "source": "AG2 CodeExecution Tool + Sandbox", "state": "needs_setup", "enabled": False, "note": "AG2 有代码执行工具接口；当前没有配置隔离沙盒。"},
    {"id": "file.write", "group": "执行操作", "risk": "高 · 确认", "description": "写入 Demo 工作区", "source": "受限文件 Connector + 确认队列", "state": "ready", "enabled": True, "note": "只写 demo_workspace；目标已存在时拒绝覆盖。"},
    {"id": "email.send", "group": "执行操作", "risk": "高 · 确认", "description": "发送邮件", "source": "邮件 API / MCP Connector", "state": "needs_setup", "enabled": False, "note": "未配置邮件服务和收件人策略。"},
    {"id": "calendar.create", "group": "执行操作", "risk": "高 · 确认", "description": "创建日历事件", "source": "Calendar API / MCP Connector", "state": "needs_setup", "enabled": False, "note": "未配置日历服务。"},
    {"id": "task.create", "group": "执行操作", "risk": "中", "description": "创建并跟踪任务", "source": "TPAA Task Service", "state": "planned", "enabled": False, "note": "当前没有持久化任务引擎。"},
    {"id": "agent.ask", "group": "协同通信", "risk": "中高", "description": "请求另一个 Agent 协作", "source": "AG2 Agent / A2A / MCP + 信任策略", "state": "needs_setup", "enabled": False, "note": "未接入远端目录和通信。"},
    {"id": "human.approve", "group": "协同通信", "risk": "审批", "description": "人工确认副作用操作", "source": "本地工作台确认队列", "state": "ready", "enabled": True, "note": "报告写入前提供确认/取消。"},
    {"id": "team.notify", "group": "协同通信", "risk": "高 · 确认", "description": "通知团队频道", "source": "Chat / Webhook Connector", "state": "needs_setup", "enabled": False, "note": "未配置团队消息服务。"},
    {"id": "desktop.control", "group": "桌面自动化", "risk": "高 · 确认", "description": "操作 Windows 桌面", "source": "外部 Desktop Worker（非 AG2 内置）", "state": "unsupported", "enabled": False, "note": "AG2 本身不控制桌面；需单独实现 Worker。"},
    {"id": "domain.custom", "group": "专业领域", "risk": "按工具策略", "description": "研发 / 财务 / 法务 / 医疗工具", "source": "领域 API / MCP / 自定义工具", "state": "needs_setup", "enabled": False, "note": "逐项接入；医疗用途需额外资质与合规审查。"},
    {"id": "calculator.evaluate", "group": "效率工具", "risk": "低", "description": "受限数学表达式计算", "source": "本地安全计算工具", "state": "ready", "enabled": True, "note": "只解析数字和算术运算，不执行 Python。"},
    {"id": "workspace.list", "group": "文件", "risk": "低", "description": "列出 Demo 工作区文件", "source": "本地受限文件 Connector", "state": "ready", "enabled": True, "note": "仅访问 demo_workspace。"},
    {"id": "workspace.read", "group": "文件", "risk": "中", "description": "读取 Demo 工作区文本", "source": "本地受限文件 Connector", "state": "ready", "enabled": True, "note": "仅访问 demo_workspace。"},
];const groups=[...new Set(CATALOG.map(x=>x.group))];$('count').textContent=CATALOG.length;$('catalog').innerHTML=groups.map(group=>'<section class="cap-group"><h3>'+esc(group)+'</h3>'+CATALOG.filter(x=>x.group===group).map(c=>'<label class="cap"><input type="checkbox" '+(c.enabled?'checked ':'')+(c.state==='ready'?'':'disabled')+' data-cap="'+esc(c.id)+'"><span class="cap-copy"><strong>'+esc(c.id)+'</strong><small>'+esc(c.description)+'</small><small>'+esc(c.note)+'</small></span><span class="cap-status '+esc(c.state)+'">'+(c.state==='ready'?'可运行':c.state==='planned'?'规划中':c.state==='unsupported'?'不支持':'待接入')+'</span></label>').join('')+'</section>').join('');$('catalog').addEventListener('change',async e=>{const input=e.target.closest('[data-cap]');if(!input)return;const r=await fetch('/api/capabilities/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:input.dataset.cap,enabled:input.checked})});const j=await r.json();if(!r.ok){input.checked=!input.checked;alert(j.detail||'无法变更能力');return}status('能力配置已更新；新会话生效',true)});$('prompt').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}});
</script></body></html>'''


if __name__ == "__main__":
    import uvicorn
    print("AG2 capability workbench · http://127.0.0.1:8766")
    print("API key is entered in the local page and held in process memory only.")
    uvicorn.run(app, host="127.0.0.1", port=8766, log_level="warning")
