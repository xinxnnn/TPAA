"""Local AG2 run after verifying a delivered agent against the user's PHC.

Issued bundle code remains data until capability adapters are designed. The
model API credential comes solely from the user's local process environment.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ag2 import Agent
from ag2.events import ModelMessage, ModelRequest, ModelResponse, TextInput
from ag2.stream import MemoryStream

import crypto.sdk
from packages.tpaa_runtime.local_state import LocalConversationState
from packages.tpaa_runtime.model_config import from_env
from packages.tpaa_runtime.manifest import manifest_digest_of

v1 = crypto.sdk.v1


async def run(publication: dict, phc_doc: dict, *, owner: str, user_hsm,
              tp_pk, ap_pk, prompt: str, application_id: str, agent_dir) -> str:
    if type(prompt) is not str or not prompt.strip() or len(prompt) > 8000:
        raise ValueError("请输入不超过 8000 字符的本地实验任务")
    if owner != v1.owner_of(user_hsm.pubkey()):
        raise PermissionError("本地用户密钥归属与颁发 owner 不符")
    phc = v1.from_jsonld(phc_doc)
    if v1.verify_public(phc, tp_pk=tp_pk, ap_pk=ap_pk):
        raise ValueError("本地 PHC 公开验证失败")
    if (publication.get("phcDigest") != v1.phc_digest(phc)
            or manifest_digest_of(publication["manifest"])
               != publication["manifest"]["audit"]["manifestDigest"]
            or publication["manifest"].get("did") != publication.get("did")
            or publication["manifest"].get("build", {}).get("cmi") != phc.apm.cmi
            or not publication.get("did", "").startswith("did:wba:")):
        raise ValueError("本地颁发制品与最终 PHC 不一致")
    if agent_dir is None or application_id != json.loads(
            (Path(agent_dir) / "delivery.json").read_text(encoding="utf-8"))["applicationId"]:
        raise ValueError("缺少与申请匹配的本地颁发目录")
    config = from_env()
    return await asyncio.to_thread(_run_turn, agent_dir, application_id,
                                   publication["did"], owner, config, prompt)


def _run_turn(agent_dir, application_id, did, owner, config, prompt):
    # SQLite's writer lock spans replay, model request, and commit for this agent.
    # A worker thread avoids blocking other agents on the executor's event loop.
    with LocalConversationState(agent_dir, application_id=application_id,
                                did=did, owner=owner) as state:
        return asyncio.run(_ask_and_append(state, config, prompt))


async def _ask_and_append(state, config, prompt):
    agent = Agent("issued-local-agent", "已绑定本地 PHC 的智能体；MemAuth 尚未注册。",
                  config=config, tools=[])
    stream = MemoryStream()
    events = []
    for question, answer in state.history():
        events.extend((ModelRequest([TextInput(question)]),
                       ModelResponse(ModelMessage(answer))))
    await stream.history.replace(events)
    result = await agent.ask(prompt, stream=stream)
    reply = str(result.body or "")
    state.append(prompt, reply)
    return reply


__all__ = ["run"]
