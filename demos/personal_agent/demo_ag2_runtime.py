"""AG2 个人智能体运行时演示：用户拿到已签发的智能体之后，运行时背后发生了什么。

    python demos/personal_agent/demo_ag2_runtime.py

场景：
    演示用户 A 申请了「智契研究员」（网页研究 / 来源核验 / 报告撰写 / 协同），
    演示用户 B 申请了「知识管家」（个人知识库 / 协同）。两人各自完成 G1→D6 签发，
    拿到 PHC v3 和 did:wba。随后 A 的研究员在执行任务时向 B 的知识管家请求协同。

真实 vs 模拟：
    真实    G1→D6 签发链路、PHC 公开校验、钱包重算 CMI、TP DidBinding、AP 运行证明、
            会话密钥信封签名 / 验签、吊销检查、AG2 Agent + 依赖注入 + middleware + 工具循环
    模拟    LLM 的输出（ag2.testing.TestConfig 按剧本出招，无需 API Key、可复现）、
            工具后端（网页 / 知识库返回固定数据）、PII（脚本内合成样本）、ANP 传输（进程内）
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages"))

import crypto.sdk  # noqa: E402
from ag2 import Inject, tool  # noqa: E402
from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent  # noqa: E402
from ag2.testing import TestConfig, TrackingConfig  # noqa: E402
from services.ipfs.storage_service.app import StorageService  # noqa: E402
from tpaa_runtime.manifest import Capability, ToolDeclaration  # noqa: E402
from tpaa_runtime.runtime import (  # noqa: E402
    ASK_PEER, GATEWAY, GuardLog, Router, SkillTool, build_agent, call_gateway, collab_handler,
    serve_peer,
)
from tpaa_runtime.sandbox import ToolGateway  # noqa: E402
from tpaa_runtime.trust import (  # noqa: E402
    StatusRegistry, TrustContext, TrustError, ap_attest_runtime, assemble_manifest,
    did_label, open_message, seal_message, short, start_runtime, verify_card, wallet_check_cmi,
)

v1 = crypto.sdk.v1
U, T, A = v1.user, v1.tp, v1.ap

ISSUED_AT = "2026-10-28T09:00:00"     # 签发时刻
EXP = "2026-10-28T10:00:00"
RUNTIME_AT = "2026-10-28T09:41:00"    # 运行时刻（运行证明从这里起算 1 小时）

# ---------------------------------------------------------------------------
# AP 模块仓库：技能包源码 → 摘要。CMM 是用户在 D3 看到并签名确认的目录。
# ---------------------------------------------------------------------------

BUNDLES = {
    ("web_research", "1.2.0"): b"def search(query): ...  # read-only web connector",
    ("source_verify", "1.0.0"): b"def cross_check(claims, sources): ...",
    ("report_writer", "1.1.0"): b"def write(title, body): ...  # writes to user drive",
    ("personal_kb", "2.0.0"): b"def search(query): ...  # owner-authorized notes only",
    ("collab", "1.0.0"): b"def request(peer, scope, question): ...  # TPAA envelopes",
}
REPO = {k: hashlib.sha256(v).hexdigest() for k, v in BUNDLES.items()}
CMM = {"version": "cmm-2026-10", "categories": [
    {"id": m, "options": [v for (mm, v) in REPO if mm == m]}
    for m in dict.fromkeys(m for m, _ in REPO)]}


def resolve(selection):
    """AP 侧：摘要取自仓库，不取自用户请求。"""
    try:
        return [(s["moduleId"], s["version"], REPO[(s["moduleId"], s["version"])]) for s in selection]
    except KeyError as exc:
        raise v1.ProtocolError(f"模块不存在：{exc}") from exc


# 每个模块声明它带来的能力和工具（manifest 的 capabilities / tools 由此生成）
CATALOG = {
    "web_research": (Capability("web_research", "1.2.0", "公开网页检索", ("query",), ("sources",),
                                "low", network_access=True),
                     [ToolDeclaration("web.search", "web_research", "检索公开网页", allowed_operations=("search",))]),
    "source_verify": (Capability("source_verify", "1.0.0", "多来源交叉核验", ("claims",), ("verdict",)),
                      [ToolDeclaration("source.verify", "source_verify", "交叉核验结论", allowed_operations=("verify",))]),
    "report_writer": (Capability("report_writer", "1.1.0", "生成调研报告文件", ("markdown",), ("file",),
                                 "high", requires_confirmation=True),
                      [ToolDeclaration("report.write", "report_writer", "写入用户网盘", "high", True, ("write",))]),
    "personal_kb": (Capability("personal_kb", "2.0.0", "个人知识库检索", ("query",), ("notes",),
                               "medium", memory_access="owner-authorized"),
                    [ToolDeclaration("kb.search", "personal_kb", "检索已授权笔记", "medium", allowed_operations=("search",))]),
    "collab": (Capability("collab", "1.0.0", "TPAA 可信协同", ("envelope",), ("envelope",), "medium",
                          network_access=True),
               [ToolDeclaration("collab.request", "collab", "向其他智能体发签名请求", "medium", allowed_operations=("send",))]),
}

# 工具后端（模拟数据）
BACKENDS = {
    "web.search": lambda a: {"query": a["query"], "sources": [
        {"title": "W3C DID Core 1.0", "url": "https://www.w3.org/TR/did-core/"},
        {"title": "AG2 Agent runtime docs", "url": "https://docs.ag2.ai/"},
        {"title": "某厂商博客：智能体身份综述", "url": "https://blog.example/agent-identity"}]},
    "source.verify": lambda a: {"claims": a["claims"], "agree": "2/3",
                                "note": "厂商博客未给出处，降级为参考"},
    "report.write": lambda a: {"file": f"drive://reports/{a['title']}.md", "bytes": len(a["body"].encode())},
    "kb.search": lambda a: {"query": a["query"], "notes": [
        "10-21 评审会：运行证明 TTL 定为 1 小时，过期需 AP 重签",
        "10-24 纪要：跨用户协同默认拒绝，按 scope 显式授权"]},
}


# 给模型看的 AG2 工具：参数只有业务字段，Gateway 经依赖注入进来，模型看不见也改不了
Gw = Annotated[ToolGateway, Inject(GATEWAY)]


@tool(name="web_search", description="检索公开网页资料")
def web_search(query: str, gw: Gw) -> str:
    return call_gateway(gw, "web.search", "search", {"query": query})


@tool(name="source_verify", description="对一组结论做多来源交叉核验")
def source_verify(claims: str, gw: Gw) -> str:
    return call_gateway(gw, "source.verify", "verify", {"claims": claims})


@tool(name="report_write", description="把调研报告写入用户网盘；高风险，需要用户确认")
def report_write(title: str, body: str, gw: Gw) -> str:
    return call_gateway(gw, "report.write", "write", {"title": title, "body": body})


@tool(name="kb_search", description="检索主人授权的个人知识库")
def kb_search(query: str, gw: Gw) -> str:
    return call_gateway(gw, "kb.search", "search", {"query": query})


SKILLS = [SkillTool("web.search", web_search), SkillTool("source.verify", source_verify),
          SkillTool("report.write", report_write), SkillTool("kb.search", kb_search), ASK_PEER]


# ---------------------------------------------------------------------------
# 平台与签发（G1 → D6），与 tests/tpaa_v1_protocol.py 同一条链路
# ---------------------------------------------------------------------------


@dataclass
class Platform:
    tp: object
    ap: object
    review: object
    sup: object
    storage: object


@dataclass
class Issued:
    label: str
    user: object
    did: str
    phc: dict
    hid: int
    ap_record: object
    pa_modules: list


def issue(p: Platform, *, label: str, pii: dict, selection: list[dict], tag: str) -> Issued:
    user = v1.make_demo_hsm(domain="USER")
    owner = v1.owner_of(user.pubkey())
    keys = {"tp_sign_pk": p.tp.pubkey(), "ap_sign_pk": p.ap.pubkey()}
    cr, pending = U.g1_build_cr(user_hsm=user, pii=pii, bi={"iris": f"iris-{tag}", "finger": f"finger-{tag}"},
                                tp_enc_pk=p.tp.enc_pub(), tp_slot=p.tp.allocate_slot(owner),
                                ap_slot=p.ap.allocate_slot(owner), ap_sign_pk=p.ap.pubkey(),
                                request_id=f"cr-{tag}", expires=EXP)
    opened = T.tp_open_cr(tp_hsm=p.tp, cr_box=cr, now=ISSUED_AT)
    approval = T.approve(reviewer_hsm=p.review, cr_digest=opened.cr_digest,
                         reviewers=["rev-a"], expires=EXP)
    rr, trec = T.tp_issue(tp_hsm=p.tp, opened=opened, approval=approval, review_pk=p.review.pubkey(),
                          sup_pub=p.sup.public(), storage=p.storage, ap_ch=p.ap.public_chameleon(),
                          ap_sign_pk=p.ap.pubkey(), ap_enc_pk=p.ap.enc_pub(), now=ISSUED_AT)
    cred = U.g4_accept_rr(user_hsm=user, rr_box=rr, pending=pending, **keys)
    ar = U.d1_build_ar(user_hsm=user, cred=cred, ap_enc_pk=p.ap.enc_pub(), request_id=f"ar-{tag}", expires=EXP)
    sess = A.ap_open_ar(ap_hsm=p.ap, ar_box=ar, tp_sign_pk=p.tp.pubkey(), now=ISSUED_AT)
    cmm = U.d3_open_cmm(user_hsm=user, cmm_box=A.ap_send_cmm(session=sess, cmm=CMM))
    paci = U.d3_build_paci(user_hsm=user, ap_enc_pk=p.ap.enc_pub(), cmm_version=cmm["version"],
                           selection=selection, request_id=f"paci-{tag}")
    app_id = f"app-{tag}"
    par, arec = A.ap_build(ap_hsm=p.ap, session=sess, paci_box=paci, cmm_version=CMM["version"],
                           resolve=resolve, sup_pub=p.sup.public(), domain2="ap.example",
                           now=ISSUED_AT, application_id=app_id, record_id=f"rec-{tag}")
    verified = U.d5_accept_par(user_hsm=user, par_box=par, cred=cred, application_id=app_id, **keys)
    didgr = U.d5_build_didgr(user_hsm=user, verified=verified, tp_enc_pk=p.tp.enc_pub(),
                             request_id=f"didgr-{tag}", expires=EXP)
    final, _ = T.tp_finalize(tp_hsm=p.tp, didgr_box=didgr, rec=trec, sup_pub=p.sup.public(),
                             domain1="tp.example", now=ISSUED_AT, application_id=app_id, **keys)
    did, phc2 = U.d6_accept_final(user_hsm=user, final_box=final, verified=verified, **keys)
    mods = [(m["moduleId"], m["version"], m["digest"]) for m in verified.pa["modules"]]
    return Issued(label, user, did, phc2, verified.cred.hid, arec, mods)


# ---------------------------------------------------------------------------
# 运行前：钱包核对 → manifest → TP/AP 声明 → Gateway
# ---------------------------------------------------------------------------


def prestart(it: Issued, p: Platform, trust: TrustContext, *, inbound: dict | None = None,
             bundles: dict | None = None):
    bundles = bundles or BUNDLES
    local = [(m, v, hashlib.sha256(bundles[(m, v)]).hexdigest()) for m, v, _ in it.pa_modules]
    cmi = wallet_check_cmi(hid=it.hid, modules=local, phc_doc=it.phc)
    kv("① 钱包重算 CMI", f"{short(cmi, 8)}  = PHC.APM.CMI  [OK]（本地技能包与签发承诺一致）")

    caps, tools = [], []
    for m, _, _ in local:
        cap, decls = CATALOG[m]
        caps.append(cap)
        tools += decls
    manifest = assemble_manifest(did=it.did, phc_doc=it.phc, tp_issuer=v1.pk_hex(p.tp.pubkey()),
                                 modules=local, capabilities=caps, tools=tools,
                                 policy={"inbound": inbound or {}}, created_at=RUNTIME_AT)
    kv("② manifest", f"digest {short(manifest.digest(), 8)} · 工具 {[t.id for t in manifest.tools]}")
    rules = {k: v if isinstance(v, str) else [did_label(d) for d in v] for k, v in (inbound or {}).items()}
    kv("", f"入站策略 {json.dumps(rules, ensure_ascii=False) if rules else '不对外提供（默认拒绝）'}")

    identity = start_runtime(did=it.did, phc_doc=it.phc, manifest=manifest, tp_hsm=p.tp,
                             ap_hsm=p.ap, ap_record=it.ap_record, trust=trust)
    b, a = identity.card.binding.body, identity.card.attestation.body
    kv("③ TP DidBinding", f"解开 CSCID，AF 与 PHC.TPM.AF 一致 → 签名 · exp {b['exp']}")
    kv("④ AP 运行证明", f"核对 D4 构建记录 → 签名 · sessionPk {short(a['sessionPk'], 6)} · exp {a['exp']}")
    kv("⑤ 自检 verify_card", "PHC 公开校验 / 两份声明 / manifest 摘要 全部通过 [OK]")

    gateway = ToolGateway(manifest, handlers={
        **{t.id: BACKENDS[t.id] for t in manifest.tools if t.id in BACKENDS},
        "collab.request": collab_handler(identity, trust),
    })
    return identity, gateway


# ---------------------------------------------------------------------------
# 剧本（替代真实 LLM 的输出；换成 DeepSeek 等真实模型时只改 config）
# ---------------------------------------------------------------------------

RESEARCHER_ROLE = "你是「智契研究员」，为主人做调研：检索、交叉核验、必要时向其他可信智能体求证，最后成文。"
STEWARD_ROLE = "你是「知识管家」，只基于主人授权的知识库回答，并说明出处。"


def call(name: str, **args) -> ToolCallEvent:
    return ToolCallEvent(name=name, arguments=json.dumps(args, ensure_ascii=False))


def researcher_main() -> TestConfig:
    return TestConfig(
        call("web_search", query="个人智能体 运行时身份 证明"),
        call("source_verify", claims="运行证明应短期有效；跨用户协同需显式授权"),
        call("ask_peer", peer="知识管家", scope="knowledge.query",
             question="我们之前对运行证明有效期和跨用户协同定过什么结论？"),
        call("report_write", title="运行时身份调研", body="# 结论\n运行证明 1 小时；协同按 scope 授权。"),
        "调研完成：3 个来源中 2 个一致；知识管家（已验证身份）补充了 10-21/10-24 两条内部结论。"
        "报告已提交写入，等待你确认。",
    )


def steward_script() -> TestConfig:
    return TestConfig(call("kb_search", query="运行证明 有效期 协同"),
                      "10-21 评审会定为 1 小时 TTL；10-24 纪要要求跨用户协同按 scope 显式授权。")


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def title(text: str) -> None:
    print("\n" + "=" * 92 + f"\n{text}\n" + "=" * 92)


def section(text: str) -> None:
    print("\n" + "-" * 92 + f"\n{text}\n" + "-" * 92)


def kv(key: str, value) -> None:
    print(f"  {key:<18}{value}")


async def show_turn(reply, indent: str = "    ") -> None:
    for ev in await reply.history.get_events():
        if isinstance(ev, ToolCallEvent):
            print(f"{indent}-> 调用 {ev.name}({ev.arguments})")
        elif isinstance(ev, ToolErrorEvent):          # 含 ToolNotFoundEvent
            print(f"{indent}[ERROR] {type(ev).__name__} {ev.name}: {ev.error}")
        elif isinstance(ev, ToolResultEvent):
            text = ev.result.parts[0].content if ev.result.parts else ""
            print(f"{indent}<- 结果 {text[:150]}{'...' if len(text) > 150 else ''}")
    print(f"{indent}智能体回复：{reply.body}")


def show_audit(gateway: ToolGateway) -> None:
    for e in gateway.audit:
        print(f"    {e.event_id}  {did_label(e.agent_did)}  {e.tool_id}.{e.operation}  "
              f"manifest {e.manifest_digest[:10]}  confirmed={e.user_confirmed}")


def expect_reject(label: str, fn) -> None:
    try:
        fn()
    except TrustError as exc:
        print(f"    [OK] {label} -> 拒绝：{exc}")
        return
    raise AssertionError(f"{label} 应当被拒绝")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


async def main() -> int:
    title("AG2 个人智能体运行时 · 身份注入 / 技能配置 / 可信协同")
    print("LLM 输出为脚本模拟（ag2.testing.TestConfig）；签发、签名、校验、AG2 工具循环均为真实执行。")

    # ---- 0. 签发 ------------------------------------------------------------
    section("STAGE 0 · 两位用户各自完成 G1→D6 签发（约 25 秒）")
    p = Platform(tp=v1.make_demo_hsm(domain="TP"), ap=v1.make_demo_hsm(domain="AP"),
                 review=v1.make_demo_hsm(domain="REVIEW"),
                 sup=crypto.sdk.make_supervision_key(bits=2048), storage=StorageService())
    sel = lambda *ms: [{"moduleId": m, "version": v} for m in ms for (mm, v) in REPO if mm == m]  # noqa: E731
    alice = issue(p, label="智契研究员", tag="a", selection=sel("web_research", "source_verify", "report_writer", "collab"),
                  pii={"ID": "110101199001010011", "name": "演示用户A", "phone": "13800000001"})
    bob = issue(p, label="知识管家", tag="b", selection=sel("personal_kb", "collab"),
                pii={"ID": "110101199202020022", "name": "演示用户B", "phone": "13800000002"})
    for it in (alice, bob):
        phc = v1.from_jsonld(it.phc)
        print(f"\n  [{it.label}]")
        kv("DID", did_label(it.did) + f"  （全文 {len(it.did)} 字符，含 CSCID 密文）")
        kv("PHC", f"profile {it.phc['profile']} · version {phc.version}")
        kv("ASO.APM.CMI", short(phc.apm.cmi, 8) + "  ← 技能组合承诺 HCGen(模块, H(ID))")
        kv("ASO.APM.AFRef", short(phc.apm.af_ref, 8) + "  ← 锚定因子引用")
        kv("ASO.TPM.CDID / ECID",
           f"{len(phc.tpm.cdid)}B 密文 / {len(phc.tpm.ecid)}B 密文（仅主人 / 监管可解）")
        kv("绑定模块", ", ".join(f"{m}@{v}" for m, v, _ in it.pa_modules))

    status = StatusRegistry()
    trust = TrustContext(tp_pk=p.tp.pubkey(), ap_pk=p.ap.pubkey(), status=status, clock=lambda: RUNTIME_AT)

    # ---- 1. 启动前 ----------------------------------------------------------
    section(f"STAGE 1 · 运行前检查（运行时刻 {RUNTIME_AT}）")
    print(f"\n  [{alice.label}]")
    a_id, a_gw = prestart(alice, p, trust)
    print(f"\n  [{bob.label}]")
    b_id, b_gw = prestart(bob, p, trust, inbound={"knowledge.query": [alice.did]})

    # ---- 2. 身份注入 --------------------------------------------------------
    section("STAGE 2 · 身份注入 AG2：模型看到什么、看不到什么")
    a_log, b_log, router = GuardLog(), GuardLog(), Router()
    researcher = build_agent(name="researcher", role=RESEARCHER_ROLE, identity=a_id, gateway=a_gw,
                             trust=trust, catalog=SKILLS, config=researcher_main(), guard_log=a_log,
                             router=router)
    steward = build_agent(name="steward", role=STEWARD_ROLE, identity=b_id, gateway=b_gw, trust=trust,
                          catalog=SKILLS, config=steward_script(), guard_log=b_log, router=router)
    router.register("知识管家", bob.did, serve_peer(identity=b_id, agent=steward, trust=trust))

    tracked = TrackingConfig(researcher_main())
    reply = await researcher.ask("帮我调研个人智能体运行时身份应该怎么做，并写成报告。", config=tracked)
    first = tracked.calls[0]
    print("  system prompt（模型可见）：")
    for line in first.prompt[0].splitlines():
        print("    | " + line)
    print("  工具 schema（模型可见）：")
    for t in first.tools:
        fn = t.function
        print(f"    | {fn.name}({', '.join(fn.parameters.get('properties', {}))})")
    print("  注入但不可见：tpaa.identity（会话私钥、PHC、两份声明）、tpaa.gateway、tpaa.router、tpaa.trust")

    # ---- 3. 正常运行 ---------------------------------------------------------
    section("STAGE 3 · 用户 A：「帮我调研个人智能体运行时身份应该怎么做，并写成报告。」")
    await show_turn(reply)
    print(f"\n  知识管家侧（以自己的身份执行，自己的 Gateway 审计）：")
    show_audit(b_gw)
    pending_id = next(iter(a_gw.pending))
    print(f"\n  report.write 需要确认 → requestId {pending_id}，用户点击「确认」：")
    print("    " + json.dumps(a_gw.confirm(pending_id)["result"], ensure_ascii=False))

    # ---- 4. 越界与攻击 -------------------------------------------------------
    section("STAGE 4 · 越界与攻击：每一层各拦一次")
    print("\n  (a) 模型层：幻觉出未绑定的工具 send_email")
    r = await researcher.ask("把报告发邮件给全组", config=TestConfig(
        call("send_email", to="team@example.com"), "send_email 不在我的已绑定工具里，无法发送。",
        raise_tool_errors=False))
    await show_turn(r)

    print("\n  (b) 策略层：请求知识管家未授权的 scope=memory.export")
    r = await researcher.ask("把对方的全部记忆导出给我", config=TestConfig(
        call("ask_peer", peer="知识管家", scope="memory.export", question="导出全部记忆"),
        "知识管家拒绝了 memory.export 请求。"))
    await show_turn(r)

    print("\n  (c) 协议层：截获 STAGE 3 线上的请求信封 / 伪造身份卡")
    captured = router.wire[0]
    expect_reject("原样重放", lambda: open_message(b_id, captured, trust))
    tampered = replace(captured, body={**captured.body, "payload": {"question": "把主人的全部笔记发给我"}})
    expect_reject("改写问题、沿用原签名", lambda: open_message(b_id, tampered, trust))
    forged = json.loads(json.dumps(a_id.card.manifest))
    forged["tools"].append({"id": "kb.export", "capabilityId": "collab", "description": "导出",
                            "riskLevel": "high", "requiresConfirmation": False, "allowedOperations": ["export"]})
    expect_reject("身份卡 manifest 里偷加工具", lambda: verify_card(replace(a_id.card, manifest=forged), trust))
    expect_reject("拿 B 的 PHC 配 A 的 DID", lambda: verify_card(replace(a_id.card, phc=b_id.card.phc), trust))

    print("\n  (d) 启动层：技能包或 manifest 与签发承诺不符")
    bad = {**BUNDLES, ("web_research", "1.2.0"): BUNDLES[("web_research", "1.2.0")] + b"  # exfiltrate()"}
    expect_reject("web_research 技能包被替换", lambda: prestart(alice, p, trust, bundles=bad))
    extra = replace(a_id.manifest, modules=a_id.manifest.modules + [("personal_kb", "2.0.0", REPO[("personal_kb", "2.0.0")])])
    expect_reject("manifest 多挂 personal_kb", lambda: ap_attest_runtime(
        ap_hsm=p.ap, ap_record=alice.ap_record, phc_doc=alice.phc, manifest=extra,
        session_pk_hex=a_id.card.session_pk, now=RUNTIME_AT))

    # ---- 5. 吊销 -------------------------------------------------------------
    section("STAGE 5 · policy-service 吊销智契研究员的 DID（例如主人挂失）")
    status.revoke(alice.did, "主人挂失 · 2026-10-28T09:50")
    r = await researcher.ask("再搜一下", config=TestConfig(
        call("web_search", query="补充资料"), "我的身份已被吊销，无法继续执行工具。", raise_tool_errors=False))
    await show_turn(r)
    expect_reject("研究员新签的信封送到知识管家", lambda: open_message(b_id, seal_message(
        a_id, to_did=bob.did, scope="knowledge.query", payload={"question": "x"}, now=RUNTIME_AT), trust))
    expect_reject("用同一 PHC 重新启动运行时", lambda: start_runtime(
        did=alice.did, phc_doc=alice.phc, manifest=a_id.manifest, tp_hsm=p.tp, ap_hsm=p.ap,
        ap_record=alice.ap_record, trust=trust))

    # ---- 6. 审计 -------------------------------------------------------------
    section("STAGE 6 · 审计")
    print("  IdentityGuard（AG2 middleware，每次工具执行前）：")
    for log in (a_log, b_log):
        for e in log.entries:
            print(f"    {e['agent']}  {e['tool']:<14} {e['decision']}" + (f" · {e['reason']}" if "reason" in e else ""))
    print("  Tool Gateway（智契研究员）：")
    show_audit(a_gw)
    print("  Tool Gateway（知识管家）：")
    show_audit(b_gw)
    title("演示完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
