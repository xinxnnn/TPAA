"""把 TPAA 身份接进 AG2 Agent：身份注入、技能装配、调用前守卫、可信协同。

LLM 永远看不到身份材料本身：
    * RuntimeIdentity / ToolGateway / Router 经 AG2 依赖注入（Inject）交给工具，
      不出现在工具 schema 里，模型无法伪造或改写；
    * system prompt 只放 identity.summary()（DID 缩写、CMI 缩写、可用工具）；
    * 只有 manifest 声明的工具才注册给 Agent —— 未绑定的技能对模型来说根本不存在。

每次工具调用经过两道关：
    IdentityGuard（AG2 middleware）  这是谁：吊销状态、运行证明时效、调用者与 manifest 主体一致
    ToolGateway                    能做什么：工具 / 操作白名单、高风险确认、审计
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Annotated, Any, Awaitable, Callable

from ag2 import Agent, Inject, Middleware, tool
from ag2.config import ModelConfig
from ag2.events import ToolErrorEvent
from ag2.middleware.base import BaseMiddleware

from .sandbox import GatewayError, ToolGateway
from .trust import (
    Envelope, RuntimeIdentity, TrustContext, TrustError, did_label, open_message, seal_message,
)

IDENTITY, GATEWAY, ROUTER, TRUST = "tpaa.identity", "tpaa.gateway", "tpaa.router", "tpaa.trust"


# ---------------------------------------------------------------------------
# 调用前守卫
# ---------------------------------------------------------------------------


@dataclass
class GuardLog:
    entries: list[dict] = field(default_factory=list)


class IdentityGuard(BaseMiddleware):
    """每次工具执行前复核身份；不过则返回 ToolErrorEvent，工具函数不会被调用。"""

    def __init__(self, event, context, *, log: GuardLog) -> None:
        super().__init__(event, context)
        self.log = log

    async def on_tool_execution(self, call_next, event, context):
        identity: RuntimeIdentity = context.dependencies[IDENTITY]
        gateway: ToolGateway = context.dependencies[GATEWAY]
        trust: TrustContext = context.dependencies[TRUST]
        entry = {"agent": did_label(identity.did), "tool": event.name}
        try:
            trust.status.check(identity.did)
            if identity.card.attestation.body["exp"] <= trust.clock():
                raise TrustError("运行证明已过期，需要 AP 重新签发")
            if gateway.manifest.did != identity.did:
                raise TrustError("调用者与 Tool Gateway 的 manifest 主体不一致")
        except TrustError as exc:
            self.log.entries.append({**entry, "decision": "deny", "reason": str(exc)})
            return ToolErrorEvent(parent_id=event.id, name=event.name, error=exc)
        self.log.entries.append({**entry, "decision": "allow"})
        return await call_next(event, context)


# ---------------------------------------------------------------------------
# 技能 → AG2 工具
# ---------------------------------------------------------------------------


def call_gateway(gateway: ToolGateway, tool_id: str, operation: str, args: dict) -> str:
    """AG2 工具的统一出口：真正的执行与审计都在 Tool Gateway 里。"""
    try:
        return json.dumps(gateway.request(tool_id, operation, args), ensure_ascii=False)
    except GatewayError as exc:
        return json.dumps({"status": "denied", "toolId": tool_id, "reason": str(exc)}, ensure_ascii=False)


@dataclass(frozen=True)
class SkillTool:
    """技能目录里的一项：manifest 的 tool_id ↔ 给模型看的 AG2 工具。"""
    tool_id: str
    ag2_tool: Any


def tools_for(manifest, catalog: list[SkillTool]) -> list[Any]:
    """只装配 manifest 声明过的工具。目录里有、manifest 里没有的，一律不注册。"""
    declared = {t.id for t in manifest.tools}
    return [s.ag2_tool for s in catalog if s.tool_id in declared]


@tool(name="summarize_text", description="对输入文本生成确定性摘要")
def summarize_text(text: str, gateway: Annotated[ToolGateway, Inject(GATEWAY)]) -> str:
    return call_gateway(gateway, "summarize.run", "run", {"text": text})


@tool(name="translate_text", description="按指定语言处理输入文本")
def translate_text(text: str, language: str,
                   gateway: Annotated[ToolGateway, Inject(GATEWAY)]) -> str:
    return call_gateway(gateway, "translate.run", "run", {"text": text, "language": language})


LOCAL_TEST_SKILLS = [
    SkillTool("summarize.run", summarize_text),
    SkillTool("translate.run", translate_text),
]


def system_prompt(identity: RuntimeIdentity, role: str) -> str:
    s = identity.summary()
    return "\n".join([
        role,
        f"运行身份：{s['did']}（PHC v{s['phcVersion']}，CMI {s['cmi']}，运行证明有效至 {s['attestationExp']}）。",
        f"已绑定技能：{', '.join(s['tools'])}。只能通过提供给你的工具行动；不要声称拥有其他能力。",
        "工具返回 confirmation_required 时，说明需要用户确认，不要声称已完成。",
        "工具返回 denied / 错误时，如实告诉用户被拒绝的原因。",
    ])


def build_agent(*, name: str, role: str, identity: RuntimeIdentity, gateway: ToolGateway,
                trust: TrustContext, catalog: list[SkillTool], config: ModelConfig,
                guard_log: GuardLog, router: "Router | None" = None) -> Agent:
    gateway.state_check = lambda: identity.did not in trust.status.revoked
    gateway.preflight()
    deps = {IDENTITY: identity, GATEWAY: gateway, TRUST: trust}
    if router is not None:
        deps[ROUTER] = router
    return Agent(name, system_prompt(identity, role), config=config,
                 tools=tools_for(identity.manifest, catalog),
                 middleware=[Middleware(IdentityGuard, log=guard_log)], dependencies=deps)


# ---------------------------------------------------------------------------
# 可信协同
# ---------------------------------------------------------------------------


PeerHandler = Callable[[Envelope], Awaitable[Envelope]]


@dataclass
class Router:
    """进程内的 ANP 传输替身：只负责把信封送到对端，不做任何信任判断。"""
    directory: dict[str, str] = field(default_factory=dict)          # 别名 → DID
    handlers: dict[str, PeerHandler] = field(default_factory=dict)   # DID → 对端入口
    wire: list[Envelope] = field(default_factory=list)               # 线上流过的信封（演示重放用）

    def register(self, alias: str, did: str, handler: PeerHandler) -> None:
        self.directory[alias] = did
        self.handlers[did] = handler

    async def deliver(self, env: Envelope) -> Envelope:
        self.wire.append(env)
        handler = self.handlers.get(env.body["to"])
        if handler is None:
            raise TrustError("对端不在线")
        return await handler(env)


def serve_peer(*, identity: RuntimeIdentity, agent: Agent, trust: TrustContext) -> PeerHandler:
    """对端入口：先验信封，再让自己的 AG2 Agent 以自己的身份作答，最后签名回信。"""

    async def handle(env: Envelope) -> Envelope:
        payload = open_message(identity, env, trust)          # 不过就抛，请求方工具收到拒绝
        reply = await agent.ask(payload["question"])
        return seal_message(identity, to_did=env.body["from"], scope=env.body["scope"],
                            payload={"answer": reply.body}, now=trust.clock(),
                            reply_to=env.body["nonce"])

    return handle


def collab_handler(identity: RuntimeIdentity, trust: TrustContext) -> Callable[[dict], dict]:
    """Tool Gateway 里 collab.request 的处理器：只负责签出信封，发送由工具异步完成。"""

    def handler(args: dict) -> dict:
        env = seal_message(identity, to_did=args["to"], scope=args["scope"],
                           payload={"question": args["question"]}, now=trust.clock())
        return {"envelope": env}

    return handler


@tool(name="ask_peer", description="向另一个经过 TPAA 认证的智能体发起协同请求。peer 用通讯录别名；scope 是请求的能力范围。")
async def ask_peer(
    peer: str,
    scope: str,
    question: str,
    identity: Annotated[RuntimeIdentity, Inject(IDENTITY)],
    gateway: Annotated[ToolGateway, Inject(GATEWAY)],
    router: Annotated[Router, Inject(ROUTER)],
    trust: Annotated[TrustContext, Inject(TRUST)],
) -> str:
    to_did = router.directory.get(peer)
    if to_did is None:
        return json.dumps({"status": "denied", "reason": f"通讯录里没有 {peer}"}, ensure_ascii=False)
    try:
        sealed = gateway.request("collab.request", "send",
                                 {"to": to_did, "scope": scope, "question": question})
        reply_env = await router.deliver(sealed["result"]["envelope"])
        answer = open_message(identity, reply_env, trust)
    except (GatewayError, TrustError) as exc:
        return json.dumps({"status": "denied", "peer": peer, "reason": str(exc)}, ensure_ascii=False)
    return json.dumps({"status": "verified", "peer": peer, "peerDid": did_label(to_did),
                       "peerCmi": reply_env.sender_card.manifest["build"]["cmi"][:16],
                       **answer}, ensure_ascii=False)


ASK_PEER = SkillTool("collab.request", ask_peer)


__all__ = ["IDENTITY", "GATEWAY", "ROUTER", "TRUST", "GuardLog", "IdentityGuard", "SkillTool",
           "call_gateway", "tools_for", "system_prompt", "build_agent", "Router", "serve_peer",
           "collab_handler", "ask_peer", "ASK_PEER"]
