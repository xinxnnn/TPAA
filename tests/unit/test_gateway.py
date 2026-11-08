"""gateway 的领域规则。

★ 这个文件的核心不是"gateway 能把答案送回去"，
  而是"gateway 在什么情况下**不送**"。

    出口卡口拦下的东西，一个字节都不能出去
    类别不答应，就回一句明确的拒绝，而不是沉默
    本节点没有这个实例，就说没有，不猜
    对岸不可达，就留痕等下轮，不假装成功

一个只测成功路径的 gateway 测试，等于在证明"转发器能转发"。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import chain_env, load_service  # noqa: E402

# ---------------------------------------------------------------------------
# 假端口：不牵扯任何真实服务，只验规则
# ---------------------------------------------------------------------------


class FakeChannel:
    def __init__(self, tickets=None) -> None:
        self.pending = list(tickets or [])
        self.sent: dict[str, dict] = {}
        self.fail_answer = False

    def pull(self, *, responder: str, state: str = "pending", limit: int = 100):
        ents = load_service("gateway", "domain.entities")
        return self.pending[:limit]

    def answer(self, *, ticket_id: str, responder: str, answer: dict) -> dict:
        if self.fail_answer:
            raise RuntimeError("对岸 503")
        self.sent[ticket_id] = dict(answer)
        return {"state": "answered"}

    def probe(self):
        return True, "fake"


class FakeAssist:
    def __init__(self, answer=None, raises=None) -> None:
        self.answer = answer if answer is not None else {
            "did": "did:tpaa:sub:000002", "parentDid": "did:tpaa:primary:000001",
            "agentType": "sub", "state": "active",
            "phcJson": '{"a":1}', "phcDigest": "d" * 64}
        self.raises = raises
        self.seen: list[dict] = []

    def answer_assist(self, *, kind: str, payload: dict) -> dict:
        self.seen.append({"kind": kind, "payload": dict(payload)})
        if self.raises:
            raise self.raises
        return dict(self.answer)


class FakeStop:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def stop(self, *, root_did, revoked, case_ref, reason):
        self.calls.append({"root_did": root_did, "revoked": list(revoked),
                           "case_ref": case_ref})
        ports = load_service("gateway", "domain.ports")
        return ports.StopOutcome(stopped=[root_did], already=[], not_local=[])


class FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        self.rows.append({"kind": kind, "subject": subject, "payload": dict(payload)})
        return f"e{len(self.rows)}"

    def probe(self):
        return True, f"entries={len(self.rows)}"

    def kinds(self) -> list[str]:
        return [r["kind"] for r in self.rows]


class FixedClock:
    def now(self) -> str:
        return "2026-01-01T00:00:00"


def _ticket(kind="lineage_proof", payload=None, tid="tk-1", case="case-1"):
    ents = load_service("gateway", "domain.entities")
    return ents.InboxTicket(ticket_id=tid, kind=kind,
                            payload=payload if payload is not None else {"did": "d1"},
                            case_ref=case)


def _ctx(channel=None, assist=None, stop=None, audit=None,
         kinds=("lineage_proof",), self_id="AP", batch=50):
    wiring = load_service("gateway", "infra.wiring")
    return wiring.build_context(
        channel=channel or FakeChannel(), assist=assist or FakeAssist(),
        audit=audit or FakeAudit(), clock=FixedClock(), stop=stop,
        self_id=self_id, allowed_kinds=kinds, batch_limit=batch)


def _drain(ctx, **kw):
    return load_service("gateway", "domain.usecases").DrainOutboxUseCase(ctx).execute(**kw)


# ---------------------------------------------------------------------------
# 1. 出口卡口
# ---------------------------------------------------------------------------


def test_unregistered_field_is_blocked_and_never_sent():
    """白名单外的键：不出网、不留空答复，而是断在这里并报警。"""
    ch = FakeChannel([_ticket()])
    assist = FakeAssist(answer={"did": "d1", "parentDid": "p1",
                                "agentType": "sub", "state": "active",
                                "phcJson": "{}", "phcDigest": "d",
                                "internalPath": "/data/ap/agents/xxx"})
    ctx = _ctx(channel=ch, assist=assist)
    rep = _drain(ctx)

    assert rep.blocked == ["tk-1"], rep.blocked
    assert rep.answered == 0
    assert ch.sent == {}, "被卡口拦下的答复绝不能出现在通道上"
    assert "gateway.export_blocked" in ctx.audit.kinds()


def test_nested_value_is_blocked():
    """嵌套对象：标量白名单之外，一并拒。"""
    ch = FakeChannel([_ticket()])
    assist = FakeAssist(answer={"status": "ok", "did": "d1",
                                "extra": {"a": 1}})
    ctx = _ctx(channel=ch, assist=assist)
    rep = _drain(ctx)
    assert rep.blocked == ["tk-1"], (rep.blocked, rep.items)
    assert ch.sent == {}


def test_pem_material_is_blocked():
    ch = FakeChannel([_ticket()])
    assist = FakeAssist(answer={"status": "ok", "did": "d1",
                                "note": "-----BEGIN PRIVATE KEY-----"})
    ctx = _ctx(channel=ch, assist=assist)
    rep = _drain(ctx)
    assert rep.blocked == ["tk-1"]


def test_answer_without_status_is_blocked():
    """没有 status 的答复无法被对岸区分'给了'与'拒绝'。

    ★ 直接测卡口而不是测用例：用例总会自己补上 status='ok'，
      所以"缺 status"只能由**上游绕过用例**时才能构造出来 ——
      而那正是卡口要防的情况（它不能假设调用方是用例）。
    """
    ents = load_service("gateway", "domain.entities")
    try:
        ents.assert_exportable({"did": "d1", "parentDid": "p1"})
    except ents.ExportBlocked as exc:
        assert "status" in str(exc)
        return
    raise AssertionError("缺 status 的答复竟通过了出口卡口")


def test_whitelist_boundary_is_explicit():
    """白名单是**有限**的：多一个键都要先登记。

    这条把"AP 能给出去的东西就这些"钉住 ——
    将来谁想加一个键，会在这里先失败一次，然后去补理由。
    """
    ents = load_service("gateway", "domain.entities")
    allowed = ents.EXPORT_ALLOWED_KEYS
    assert "phcJson" in allowed and "phcDigest" in allowed
    for bad in ("trapdoor", "cscid", "identityHash", "privateKey"):
        assert bad not in allowed, f"{bad} 不该出现在出站白名单里"


# ---------------------------------------------------------------------------
# 2. 三种答复形态
# ---------------------------------------------------------------------------


def test_ok_reply_is_delivered_with_status():
    ch = FakeChannel([_ticket()])
    ctx = _ctx(channel=ch)
    rep = _drain(ctx)
    assert rep.answered == 1
    sent = ch.sent["tk-1"]
    assert sent["status"] == "ok"
    assert sent["parentDid"] == "did:tpaa:primary:000001"
    assert "gateway.answered" in ctx.audit.kinds()


def test_unsupported_kind_is_refused_not_silenced():
    """类别不答应 → 回一句明确的拒绝。

    ★ 为什么不干脆不回：工单会挂到过期，TP 以为网络问题，重开一张，撞限流。
      一句 refused 比沉默有用得多。
    """
    ch = FakeChannel([_ticket(kind="give_me_trapdoor")])
    ctx = _ctx(channel=ch, kinds=("lineage_proof",))
    rep = _drain(ctx)

    sent = ch.sent["tk-1"]
    assert sent["status"] == "refused"
    assert "give_me_trapdoor" in sent["reason"]
    assert rep.answered == 1
    assert "gateway.refused" in ctx.audit.kinds()


def test_not_local_is_reported_without_leaking_internals():
    """本机没有 → 说没有，但**不把内部原因带出网**。"""
    ch = FakeChannel([_ticket(payload={"did": "did:tpaa:sub:999999"})])
    assist = FakeAssist(raises=RuntimeError(
        "did:tpaa:sub:999999 本机缺少 phc.json —— /data/ap/agents/999 下是空的"))
    ctx = _ctx(channel=ch, assist=assist)
    rep = _drain(ctx)

    sent = ch.sent["tk-1"]
    assert sent["status"] == "not_local"
    # ★ 固定文案，且不含路径、不含原始异常
    assert sent["reason"] == "该实例不在本节点"
    assert "/data/ap" not in str(sent)

    # 原文只进审计，不出网
    detail = [r for r in ctx.audit.rows if r["kind"] == "gateway.not_local"]
    assert detail and "/data/ap" in detail[0]["payload"]["detail"]


def test_delivery_failure_keeps_ticket_pending_and_is_audited():
    """回写失败：留痕、delivered=False，不假装成功。"""
    ch = FakeChannel([_ticket()])
    ch.fail_answer = True
    ctx = _ctx(channel=ch)
    rep = _drain(ctx)
    assert rep.answered == 0
    assert rep.items[0].delivered is False
    assert "gateway.deliver_failed" in ctx.audit.kinds()


# ---------------------------------------------------------------------------
# 3. 背压与身份
# ---------------------------------------------------------------------------


def test_batch_limit_caps_work_per_round():
    """对岸灌再多，本方一轮只做这么多 —— 剩下的下轮再来。

    ★ 背压落在 `pull` 的 limit 上，而不是"全拉回来再截断"：
      积压一万张时，全拉回来会先把本方内存吃掉。
      代价是本轮看不到积压总数 —— 那件事交给 /v1/outbox/pending 单独查。
    """
    many = [_ticket(tid=f"tk-{i}") for i in range(10)]
    ch = FakeChannel(many)
    ctx = _ctx(channel=ch, batch=3)
    rep = _drain(ctx)
    assert rep.polled == 3, rep.to_json()
    assert rep.answered == 3
    assert len(ch.sent) == 3, "本轮没有多做一张"


def test_unknown_party_is_rejected_at_startup():
    """self_id 不是 TP/AP → 起不来，而不是'起来但谁也不是'。"""
    try:
        _ctx(self_id="SOMEONE")
    except Exception as exc:                             # noqa: BLE001
        assert "TP 或 AP" in str(exc)
        return
    raise AssertionError("self_id=SOMEONE 竟通过了自检")


def test_empty_allowed_kinds_is_rejected():
    """什么都不答的 gateway 没有存在意义 —— 要显式确认，不能留空。"""
    try:
        _ctx(kinds=())
    except Exception as exc:                             # noqa: BLE001
        assert "allowed_kinds" in str(exc)
        return
    raise AssertionError("空 allowed_kinds 竟通过了自检")


def test_dead_channel_is_detected_at_startup():
    """一个连不上通道的 gateway 会安静地让所有单子过期 —— 宁可起不来。"""
    ch = FakeChannel()
    ch.probe = lambda: (False, "connection refused")
    try:
        _ctx(channel=ch)
    except Exception as exc:                             # noqa: BLE001
        assert "跨域通道不可用" in str(exc)
        return
    raise AssertionError("通道不可用时竟通过了自检")


# ---------------------------------------------------------------------------
# 4. 承接吊销
# ---------------------------------------------------------------------------


def test_revocation_requires_case_ref():
    """案由必填。这是第三道校验 —— 前两道都在进程内，这一道在网络边界上。"""
    uc = load_service("gateway", "domain.usecases")
    ctx = _ctx(stop=FakeStop())
    try:
        uc.IntakeRevocationUseCase(ctx).execute(
            uc.RevocationCommand(root_did="did:tpaa:primary:1",
                                 revoked=["did:tpaa:sub:2"], case_ref=""))
    except Exception as exc:                             # noqa: BLE001
        assert "案由" in str(exc)
        return
    raise AssertionError("无案由的吊销广播竟被承接了")


def test_revocation_without_stop_port_is_refused():
    """纯协查节点：明确拒，而不是'悄悄什么都不做'。"""
    uc = load_service("gateway", "domain.usecases")
    ctx = _ctx(stop=None)
    try:
        uc.IntakeRevocationUseCase(ctx).execute(
            uc.RevocationCommand(root_did="did:tpaa:primary:1",
                                 revoked=[], case_ref="case-1"))
    except Exception as exc:                             # noqa: BLE001
        assert "纯协查节点" in str(exc)
        return
    raise AssertionError("缺 stop 端口竟承接了吊销")


def test_revocation_is_forwarded_and_audited():
    uc = load_service("gateway", "domain.usecases")
    stop = FakeStop()
    ctx = _ctx(stop=stop)
    out = uc.IntakeRevocationUseCase(ctx).execute(
        uc.RevocationCommand(root_did="did:tpaa:primary:1",
                             revoked=["did:tpaa:sub:2"], case_ref="case-1"))
    assert out.accepted is True
    assert stop.calls and stop.calls[0]["case_ref"] == "case-1"
    assert "gateway.revocation" in ctx.audit.kinds()


# ---------------------------------------------------------------------------
# 5. 与真实服务接通：AP 此刻才真正出现在链上
# ---------------------------------------------------------------------------


def test_ap_answers_a_real_ticket_over_the_chain():
    """不是转发器测试：用真实 coordination + 真实 lifecycle。

    ★ 这条是"AP 在追溯链上缺席"这个缺口的回归。
      在 gateway 之前，工单永远停在 pending —— 没有任何东西代表 AP 应答。
    """
    with chain_env() as c:
        root, sub = c.seed()
        cu = load_service("coordination", "domain.usecases")
        t = cu.OpenTicketUseCase(c.coord_ctx).execute(
            requester="TP", responder="AP", kind="lineage_proof",
            payload={"did": sub}, case_ref="case-1")
        assert cu.GetTicketUseCase(c.coord_ctx).execute(t.ticket_id).state.value == "pending"

        rep = _drain(c.gw_ctx)

        assert rep.polled == 1 and rep.answered == 1, rep.to_json()
        got = cu.GetTicketUseCase(c.coord_ctx).execute(t.ticket_id)
        assert got.state.value == "answered"
        assert got.answer.get("status") == "ok"
        assert got.answer.get("parentDid") == root
        assert got.answer.get("phcJson")
        # 出口卡口认得这些键
        assert set(got.answer) <= {"status", "did", "parentDid", "agentType",
                                   "state", "phcJson", "phcDigest"}


def test_tp_rejects_a_refusal_instead_of_treating_it_as_proof():
    """AP 说"不"之后，TP 必须听得懂。

    ★ 这条是 CollectProofUseCase 那个静默缺口的回归：
      原来只检查 state=='answered'，于是 refused / not_local 会被当成取证成功，
      审计上还写着 case.proof_collected —— 账上成功，实际空证明。
    """
    with chain_env() as c:
        root, sub = c.seed()
        cu = load_service("coordination", "domain.usecases")
        t = cu.OpenTicketUseCase(c.coord_ctx).execute(
            requester="TP", responder="AP", kind="give_me_trapdoor",
            payload={"did": sub}, case_ref="case-1")

        # gateway 只答应 lineage_proof → 回一句 refused
        _drain(c.gw_ctx)
        got = cu.GetTicketUseCase(c.coord_ctx).execute(t.ticket_id)
        assert got.answer.get("status") == "refused"

        # supervision 侧必须拒绝采信
        su = load_service("supervision-service", "domain.usecases")
        case = su.ReportCaseUseCase(c.sup_ctx).execute(su.ReportCommand(
            subject_did=sub, reporter="r1", allegation="fraud"))
        su.FileCaseUseCase(c.sup_ctx).execute(su.FileCommand(
            case_id=case.case_id, reviewers=["a", "b"]))
        su.InvestigateUseCase(c.sup_ctx).execute(
            case_id=case.case_id, requested_by="inv1")

        # 把这张被拒的单子塞给取证，应当抛错而不是写"取证完成"
        try:
            su.CollectProofUseCase(c.sup_ctx).execute(
                case_id=case.case_id, ticket_id=t.ticket_id)
        except Exception as exc:                         # noqa: BLE001
            assert "拒绝" in str(exc) or "refused" in str(exc).lower(), str(exc)
        else:
            raise AssertionError("AP 已拒绝，TP 却当成取证成功了")

        # 且绝不能留下"取证完成"的账
        kinds = [e.kind for e in c.audit_ctx.ledger.all()]
        assert "case.proof_collected" not in kinds, kinds


__all__ = [n for n in dir() if n.startswith("test_")]
