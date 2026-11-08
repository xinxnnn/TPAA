"""AG2 运行时可信层：DidBinding / 运行证明 / 信封 / IdentityGuard。

签发材料取自 tests/tpaa_v1_protocol.shared()（同一进程只跑一遍 G1→D6）。
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))
sys.path.insert(0, str(ROOT / "tests"))

from ag2.events import ToolCallEvent  # noqa: E402
from ag2.testing import TestConfig  # noqa: E402
from tpaa_v1_protocol import NOW, shared  # noqa: E402
from tpaa_runtime.manifest import Capability, ToolDeclaration  # noqa: E402
from tpaa_runtime.runtime import GuardLog, SkillTool, build_agent, call_gateway  # noqa: E402
from tpaa_runtime.sandbox import ToolGateway  # noqa: E402
from tpaa_runtime.trust import (  # noqa: E402
    StatusRegistry, TrustContext, TrustError, ap_attest_runtime, assemble_manifest, open_message,
    seal_message, start_runtime, verify_card, wallet_check_cmi,
)

RUN_AT = "2026-10-14T10:30:00"


def _rejects(fn, needle: str) -> None:
    try:
        fn()
    except TrustError as exc:
        assert needle in str(exc), f"拒绝原因不对：{exc}"
        return
    raise AssertionError(f"应当拒绝（{needle}）")


def _env(inbound=None):
    r = shared()
    trust = TrustContext(tp_pk=r.p.tp.pubkey(), ap_pk=r.p.ap.pubkey(), status=StatusRegistry(),
                         clock=lambda: RUN_AT)
    caps = [Capability(m, v, m) for m, v, _ in r.arec.modules]
    tools = [ToolDeclaration(f"{m}.run", m, m, allowed_operations=("run",)) for m, _, _ in r.arec.modules]
    manifest = assemble_manifest(did=r.did, phc_doc=r.phc2, tp_issuer="tp", modules=list(r.arec.modules),
                                 capabilities=caps, tools=tools, policy={"inbound": inbound or {}},
                                 created_at=RUN_AT)
    return r, trust, manifest


def _start(r, trust, manifest):
    return start_runtime(did=r.did, phc_doc=r.phc2, manifest=manifest, tp_hsm=r.p.tp, ap_hsm=r.p.ap,
                         ap_record=r.arec, trust=trust)


def test_runtime_identity_binds_phc_manifest_and_session():
    r, trust, manifest = _env()
    ident = _start(r, trust, manifest)
    a = ident.card.attestation.body
    assert a["cmi"] == r.phc2["ASO"]["APM"]["CMI"] == manifest.cmi
    assert a["manifestDigest"] == manifest.digest()
    assert ident.card.binding.body["did"] == r.did
    verify_card(ident.card, trust)
    assert wallet_check_cmi(hid=r.verified.cred.hid, modules=list(r.arec.modules), phc_doc=r.phc2) == manifest.cmi


def test_wallet_and_ap_reject_skill_drift():
    r, trust, manifest = _env()
    swapped = [(m, v, "00" * 32) if i == 0 else (m, v, d) for i, (m, v, d) in enumerate(r.arec.modules)]
    _rejects(lambda: wallet_check_cmi(hid=r.verified.cred.hid, modules=swapped, phc_doc=r.phc2), "CMI")
    extra = replace(manifest, modules=manifest.modules + [("translate", "1.1.0", "cc" * 32)])
    _rejects(lambda: ap_attest_runtime(ap_hsm=r.p.ap, ap_record=r.arec, phc_doc=r.phc2, manifest=extra,
                                       session_pk_hex="00", now=RUN_AT), "模块清单")


def test_verify_card_rejects_tampering_and_expiry():
    r, trust, manifest = _env()
    card = _start(r, trust, manifest).card
    forged = json.loads(json.dumps(card.manifest))
    forged["policy"]["denyUnknownTools"] = False
    _rejects(lambda: verify_card(replace(card, manifest=forged), trust), "manifest 被改过")
    bad_att = replace(card.attestation, body={**card.attestation.body, "tools": ["*"]})
    _rejects(lambda: verify_card(replace(card, attestation=bad_att), trust), "签名无效")
    late = replace(trust, clock=lambda: "2026-10-14T12:00:00")
    _rejects(lambda: verify_card(card, late), "过期")
    trust.status.revoke(r.did, "test")
    _rejects(lambda: verify_card(card, trust), "吊销")


def test_envelope_replay_tamper_scope():
    r, trust, manifest = _env(inbound={"knowledge.query": [shared().did]})
    sender, receiver = _start(r, trust, manifest), _start(r, trust, manifest)
    env = seal_message(sender, to_did=receiver.did, scope="knowledge.query", payload={"q": 1}, now=RUN_AT)
    assert open_message(receiver, env, trust) == {"q": 1}
    _rejects(lambda: open_message(receiver, env, trust), "重放")
    tampered = replace(env, body={**env.body, "payload": {"q": 2}, "nonce": "n2"})
    _rejects(lambda: open_message(receiver, tampered, trust), "签名无效")
    other = seal_message(sender, to_did=receiver.did, scope="memory.export", payload={}, now=RUN_AT)
    _rejects(lambda: open_message(receiver, other, trust), "不对外提供")
    stray = seal_message(sender, to_did=receiver.did, scope="knowledge.query", payload={}, now=RUN_AT,
                         reply_to="never-sent")
    _rejects(lambda: open_message(receiver, stray, trust), "应答")


def test_identity_guard_blocks_tools_after_revocation():
    from ag2 import tool

    r, trust, manifest = _env()
    ident = _start(r, trust, manifest)
    first = manifest.tools[0].id
    ran = []
    gateway = ToolGateway(manifest, handlers={first: lambda a: ran.append(a) or {"ok": True}})

    @tool(name="run_first", description="t")
    def run_first(x: str) -> str:
        return call_gateway(gateway, first, "run", {"x": x})

    log = GuardLog()
    agent = build_agent(name="t", role="test", identity=ident, gateway=gateway, trust=trust,
                        catalog=[SkillTool(first, run_first)], config=TestConfig("unused"), guard_log=log)
    script = lambda: TestConfig(ToolCallEvent(name="run_first", arguments='{"x": "a"}'), "done",  # noqa: E731
                                raise_tool_errors=False)
    asyncio.run(agent.ask("go", config=script()))
    assert len(ran) == 1 and log.entries[-1]["decision"] == "allow"
    trust.status.revoke(r.did, "lost")
    asyncio.run(agent.ask("go", config=script()))
    assert len(ran) == 1, "吊销后工具不得执行"
    assert log.entries[-1]["decision"] == "deny" and "吊销" in log.entries[-1]["reason"]
    assert NOW < RUN_AT
