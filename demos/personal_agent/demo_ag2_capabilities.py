"""AG2 capability runtime demo.

This demo focuses on capabilities that are actually implemented locally:
- knowledge.search: search a small local knowledge base
- calculator.evaluate: evaluate a restricted arithmetic expression
- workspace.list/read: read files from a demo workspace
- report.draft: create an in-memory report draft
- report.write: write a draft after explicit human approval

Run without an API key (deterministic scripted model):
    python demos/personal_agent/demo_ag2_capabilities.py --scripted

Run with a real OpenAI-compatible provider (DeepSeek by default):
    $env:DEEPSEEK_API_KEY = "..."
    python demos/personal_agent/demo_ag2_capabilities.py

The model plans and calls tools. The tools do the work. AG2 does not control the
Windows desktop in this demo; desktop automation is a separate worker capability.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
import operator
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

from ag2 import Agent, tool  # noqa: E402
from ag2.config import OpenAICompletionsConfig  # noqa: E402
from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent  # noqa: E402
from ag2.testing import TestConfig  # noqa: E402

WORKSPACE = ROOT / "demo_workspace"
KNOWLEDGE = [
    {"title": "运行时设计原则", "text": "Agent 负责规划，工具负责执行，所有副作用操作需要确认。"},
    {"title": "能力边界", "text": "AG2 可以编排注册的工具，但不原生控制 Windows 桌面。桌面操作需要外部 worker。"},
    {"title": "任务状态", "text": "长任务应记录步骤、工具调用、确认请求和最终产物。"},
]


@dataclass(frozen=True)
class Capability:
    id: str
    version: str
    category: str
    risk: str
    description: str
    requires_confirmation: bool = False


CAPABILITIES = [
    Capability("knowledge.search", "1.0.0", "information", "low", "Search the local knowledge base."),
    Capability("calculator.evaluate", "1.0.0", "utility", "low", "Evaluate restricted arithmetic."),
    Capability("workspace.list", "1.0.0", "file", "low", "List files in the demo workspace."),
    Capability("workspace.read", "1.0.0", "file", "medium", "Read a text file in the demo workspace."),
    Capability("report.draft", "1.0.0", "content", "low", "Create a report draft in memory."),
    Capability("report.write", "1.0.0", "content", "high", "Write a report to the demo workspace.", True),
]

DRAFTS: dict[str, dict[str, str]] = {}
APPROVED_WRITES: dict[str, str] = {}


def _safe_calculate(expression: str) -> float | int:
    """Evaluate only numeric arithmetic; names, calls, attributes and indexing are rejected."""
    allowed = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
               ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
               ast.USub: operator.neg, ast.UAdd: operator.pos}

    def visit(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in allowed:
            return allowed[type(node.op)](visit(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in allowed:
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 12:
                raise ValueError("指数过大")
            return allowed[type(node.op)](left, right)
        raise ValueError("只允许数字、括号和 + - * / % ** 运算")

    result = visit(ast.parse(expression, mode="eval"))
    if abs(result) > 10**12:
        raise ValueError("结果超出限制")
    return result


def _safe_path(name: str) -> Path:
    path = (WORKSPACE / name).resolve()
    if path != WORKSPACE and WORKSPACE not in path.parents:
        raise ValueError("路径必须位于 demo_workspace 内")
    return path


@tool(name="knowledge_search", description="Search the local authorized knowledge base.")
def knowledge_search(query: str) -> str:
    hits = [item for item in KNOWLEDGE if any(word.lower() in item["text"].lower() for word in query.split())]
    return json.dumps({"query": query, "hits": hits}, ensure_ascii=False)


@tool(name="calculator_evaluate", description="Evaluate a safe arithmetic expression such as (12+8)*3.")
def calculator_evaluate(expression: str) -> str:
    try:
        return json.dumps({"expression": expression, "result": _safe_calculate(expression)}, ensure_ascii=False)
    except (SyntaxError, ValueError, ZeroDivisionError) as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


@tool(name="workspace_list", description="List files in the local demo workspace.")
def workspace_list() -> str:
    WORKSPACE.mkdir(exist_ok=True)
    files = [str(p.relative_to(WORKSPACE)) for p in WORKSPACE.rglob("*") if p.is_file()]
    return json.dumps({"root": str(WORKSPACE), "files": sorted(files)}, ensure_ascii=False)


@tool(name="workspace_read", description="Read a UTF-8 text file from the local demo workspace.")
def workspace_read(name: str) -> str:
    try:
        path = _safe_path(name)
        return json.dumps({"name": name, "content": path.read_text(encoding="utf-8")}, ensure_ascii=False)
    except (OSError, ValueError) as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


@tool(name="report_draft", description="Create an in-memory report draft and return its draft id.")
def report_draft(title: str, body: str) -> str:
    draft_id = f"draft-{len(DRAFTS) + 1:03d}"
    DRAFTS[draft_id] = {"title": title, "body": body}
    return json.dumps({"status": "drafted", "draftId": draft_id, "title": title}, ensure_ascii=False)


@tool(name="report_write", description="Write an approved report draft to the workspace. Always asks for approval first.")
def report_write(draft_id: str, filename: str, approved: bool = False) -> str:
    draft = DRAFTS.get(draft_id)
    if not draft:
        return json.dumps({"status": "denied", "reason": "draft not found"}, ensure_ascii=False)
    approval = APPROVED_WRITES.get(draft_id)
    if not approval:
        return json.dumps({"status": "confirmation_required", "draftId": draft_id,
                           "filename": filename, "reason": "human approval required"}, ensure_ascii=False)
    if approval != filename:
        return json.dumps({"status": "denied", "reason": "approved filename does not match request"}, ensure_ascii=False)
    try:
        path = _safe_path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {draft['title']}\n\n{draft['body']}\n", encoding="utf-8")
        return json.dumps({"status": "written", "path": str(path.relative_to(WORKSPACE))}, ensure_ascii=False)
    except (OSError, ValueError) as exc:
        return json.dumps({"status": "denied", "reason": str(exc)}, ensure_ascii=False)


TOOLS = [knowledge_search, calculator_evaluate, workspace_list, workspace_read, report_draft, report_write]


async def print_events(reply: Any) -> None:
    for event in await reply.history.get_events():
        if isinstance(event, ToolCallEvent):
            print(f"  -> TOOL {event.name}: {event.arguments}")
        elif isinstance(event, ToolResultEvent):
            parts = event.result.parts
            content = parts[0].content if parts else ""
            print(f"  <- RESULT {event.name}: {content}")
        elif isinstance(event, ToolErrorEvent):
            print(f"  !! ERROR {event.name}: {event.error}")
    print(f"  AGENT: {reply.body}\n")


def config_from_env() -> OpenAICompletionsConfig:
    api_key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not api_key:
        raise SystemExit("缺少 DEEPSEEK_API_KEY；或者使用 --scripted 运行无 API 的验证模式")
    return OpenAICompletionsConfig(
        model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key=api_key,
        base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
        temperature=0.2,
    )


def scripted_config() -> TestConfig:
    return TestConfig(
        ToolCallEvent(name="knowledge_search", arguments=json.dumps({"query": "能力边界"})),
        ToolCallEvent(name="calculator_evaluate", arguments=json.dumps({"expression": "(12+8)*3"})),
        ToolCallEvent(name="report_draft", arguments=json.dumps({
            "title": "AG2 能力验证", "body": "AG2 编排了知识检索、计算和报告草稿工具。"})),
        ToolCallEvent(name="report_write", arguments=json.dumps({
            "draft_id": "draft-001", "filename": "reports/ag2-capability-demo.md"})),
        "能力验证完成。报告写入需要人工确认。",
        raise_tool_errors=False,
    )


async def run(args: argparse.Namespace) -> None:
    WORKSPACE.mkdir(exist_ok=True)
    print("AG2 能力运行 Demo")
    print("AG2 版本：1.2.2")
    print("已配置能力：")
    for capability in CAPABILITIES:
        flag = " · confirmation" if capability.requires_confirmation else ""
        print(f"  - {capability.id}@{capability.version} [{capability.category}/{capability.risk}]{flag}")

    config = scripted_config() if args.scripted else config_from_env()
    agent = Agent(
        name="capability_demo_agent",
        prompt=("You are a personal productivity agent. Use the provided tools for local work. "
                "Do not invent tool results. Explain when an operation needs human approval."),
        config=config,
        tools=TOOLS,
    )
    prompt = args.prompt or "验证你的能力：检索能力边界，计算 (12+8)*3，并生成一份报告草稿。"
    print(f"\nUSER: {prompt}\n")
    reply = await agent.ask(prompt)
    await print_events(reply)

    pending = DRAFTS.get("draft-001")
    if pending and not APPROVED_WRITES:
        answer = "y" if args.auto_approve else input("是否批准将报告写入 demo_workspace？[y/N] ").strip().lower()
        if answer == "y":
            APPROVED_WRITES["draft-001"] = "reports/ag2-capability-demo.md"
            approved = await agent.ask("用户已批准将 draft-001 写入 reports/ag2-capability-demo.md。"
                                       "请调用 report_write，参数必须使用该草稿 ID 和已批准文件名。")
            await print_events(approved)
        else:
            print("未批准，报告保持为内存草稿，未写入文件。")

    print("能力运行验证结束。")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripted", action="store_true", help="不用 API，使用确定性模型剧本验证工具链")
    parser.add_argument("--auto-approve", action="store_true", help="自动批准报告写入，仅用于演示")
    parser.add_argument("--prompt", help="发送给 AG2 Agent 的任务")
    asyncio.run(run(parser.parse_args()))
