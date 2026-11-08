"""端到端：从「举报」到「全网停运」。

这一条链跑通，才谈得上"平台能追溯恶意用户"。它横跨六个服务与四个责任方：

    supervision(TP) → coordination(跨域) → lifecycle(AP)
                                    ↘ did(TP) / policy(跨域) / audit(跨域)

测试只走**领域层**（不起 HTTP），因为这里要证明的是**规则**：
未立案不许查、双人复核、级联不漏人、审计不可改。
HTTP 的接缝另有 `tests/integration/test_trace_api.py` 负责。

装配（六个服务、一对监管密钥）见 `tests/harness.TraceChain` ——
两套测试共用同一份装配，避免"某一侧少接了一个服务"这种沉默的偏差。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import (  # noqa: E402
    TraceChain as Chain,
    chain_env,
    identity_hash,
    load_service,
)


def _seed(c: Chain) -> tuple[str, str]:
    """建好主 + 子两只，返回 (主 DID, 子 DID)。装配细节见 harness.TraceChain.seed。"""
    return c.seed()


# ---------------------------------------------------------------------------
# 1. 全链
# ---------------------------------------------------------------------------


def test_full_trace_chain_from_report_to_stop():
    with chain_env() as c:
        root_did, sub_did = _seed(c)
        sup = load_service("supervision-service", "domain.usecases")

        # 举报
        r = sup.ReportCaseUseCase(c.sup_ctx).execute(sup.ReportCommand(
            subject_did=sub_did, reporter="victim-001",
            allegation="该子体批量骚扰用户", evidence_ref="ipfs://evidence-1"))
        case_id = r.case_id
        assert r.state == "reported"

        # 立案：两名不同复核人
        f = sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
            case_id=case_id, reviewers=["reviewer-a", "reviewer-b"],
            note="证据充分，同意立案"))
        assert f.state == "filed"

        # 协查：TP 发单
        inv = sup.InvestigateUseCase(c.sup_ctx).execute(
            case_id=case_id, requested_by="tp-officer")
        assert inv.lineage_chain == [sub_did, root_did], inv.lineage_chain

        # AP 侧应答（归属证明）
        assist = load_service("lifecycle-service", "domain.usecases").AnswerAssistUseCase(
            c.life_ctx).execute(kind="lineage_proof", payload={"did": sub_did})
        coord_uc = load_service("coordination", "domain.usecases")
        coord_uc.AnswerTicketUseCase(c.coord_ctx).execute(
            ticket_id=inv.ticket_id, responder="AP", answer=assist.answer)

        # TP 收答复
        sup.CollectProofUseCase(c.sup_ctx).execute(
            case_id=case_id, ticket_id=inv.ticket_id)

        # 揭露：CSCID → H(ID)，并用 AF 复核
        dis = sup.DiscloseUseCase(c.sup_ctx).execute(
            case_id=case_id, requested_by="tp-officer")
        assert int(dis.identity_hash, 16) == c.hid, "还原出的身份与原始身份不一致"
        assert dis.verified is True, dis.verify_note
        assert dis.state == "disclosed"

        # 取证：真去 IPFS 取一次并留摘要
        fx = sup.ForensicsUseCase(c.sup_ctx).execute(
            case_id=case_id, exported_by="tp-officer")
        assert fx.envelope_bytes > 0, "取证包里没有信封 —— 取证等于白做"
        assert len(fx.envelope_digest) == 64
        assert fx.chain_verified is True
        assert fx.state == "sealed"

        # 吊销 + 级联 + 停运
        pol = load_service("policy-service", "domain.usecases")
        out = pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
            root_did=root_did, case_ref=case_id,
            reason="主体名下智能体用于骚扰", issued_by="tp-officer"))

        assert root_did in out.revoked and sub_did in out.revoked, out.revoked
        assert out.state == "notified", out.failure
        assert set(out.notified) >= {root_did, sub_did}, out.notified

        # did 侧：子体被标为级联吊销
        sub_rec = c.did_ctx.registry.get(sub_did)
        assert sub_rec.state.value == "revoked"
        assert sub_rec.revoke_source == "cascade", "子体应记为级联吊销，而非直接吊销"

        # AP 侧：本机实例确实停了
        sub_meta = c.agent_ctx.agents.load_meta(sub_did)
        root_meta = c.agent_ctx.agents.load_meta(root_did)
        assert sub_meta.state.value == "frozen"
        assert root_meta.state.value == "frozen"

        # 审计链仍然自洽
        verify = load_service("audit-service", "domain.usecases").VerifyChainUseCase(
            c.audit_ctx).execute()
        assert verify.ok is True, f"审计链断在第 {verify.broken_at} 条：{verify.reason}"

        # 取证包导出：含协调往返与吊销
        bundle = load_service("audit-service", "domain.usecases").ExportCaseUseCase(
            c.audit_ctx).execute(case_ref=case_id,
                                 subjects=[root_did, sub_did])
        kinds = {e["kind"] for e in bundle.entries}
        assert "case.filed" in kinds
        assert "case.disclosed" in kinds
        assert "policy.revoked" in kinds
        assert bundle.verdict.ok is True
        assert len(bundle.bundle_digest) == 64


# ---------------------------------------------------------------------------
# 2. 闸门：未立案一律拒
# ---------------------------------------------------------------------------


def _case(chain: Chain, subject_did: str) -> str:
    sup = load_service("supervision-service", "domain.usecases")
    return sup.ReportCaseUseCase(chain.sup_ctx).execute(sup.ReportCommand(
        subject_did=subject_did, reporter="victim-001",
        allegation="测试用举报")).case_id


def test_every_action_is_refused_before_filing():
    with chain_env() as c:
        _, sub_did = _seed(c)
        case_id = _case(c, sub_did)
        sup = load_service("supervision-service", "domain.usecases")
        NotFiled = load_service("supervision-service", "domain.entities").NotFiled

        for name, call in (
            ("协查", lambda: sup.InvestigateUseCase(c.sup_ctx).execute(
                case_id=case_id, requested_by="x")),
            ("揭露", lambda: sup.DiscloseUseCase(c.sup_ctx).execute(
                case_id=case_id, requested_by="x")),
        ):
            try:
                call()
            except NotFiled:
                continue
            raise AssertionError(f"未立案时「{name}」竟然被放行了")

        # 取证也一样：它依赖揭露，但闸门在它自己这里也必须有
        try:
            sup.ForensicsUseCase(c.sup_ctx).execute(case_id=case_id, exported_by="x")
        except NotFiled:
            pass
        else:
            raise AssertionError("未立案时「取证」竟然被放行了")


def test_filing_requires_two_distinct_reviewers():
    with chain_env() as c:
        _, sub_did = _seed(c)
        case_id = _case(c, sub_did)
        sup = load_service("supervision-service", "domain.usecases")
        CaseError = load_service("supervision-service", "domain.entities").CaseError

        for reviewers in (["same"], ["same", "same"], ["a", " a "]):
            try:
                sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
                    case_id=case_id, reviewers=reviewers))
            except CaseError:
                continue
            raise AssertionError(f"复核人 {reviewers} 竟然通过了 —— 双人形同虚设")

        # 换两个不同的人，才允许
        out = sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
            case_id=case_id, reviewers=["a", "b"]))
        assert out.state == "filed"


def test_rejected_case_stays_rejected():
    with chain_env() as c:
        _, sub_did = _seed(c)
        case_id = _case(c, sub_did)
        sup = load_service("supervision-service", "domain.usecases")

        sup.RejectCaseUseCase(c.sup_ctx).execute(
            case_id=case_id, reviewer="reviewer-a", note="证据不足")
        try:
            sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
                case_id=case_id, reviewers=["a", "b"]))
        except Exception:                                # noqa: BLE001
            return
        raise AssertionError("已不予受理的案件竟然还能再立案")


# ---------------------------------------------------------------------------
# 3. 跨域卡口
# ---------------------------------------------------------------------------


def test_coordination_refuses_non_public_payload():
    with chain_env() as c:
        NonPublic = load_service("coordination", "domain.entities").NonPublicPayload
        uc = load_service("coordination", "domain.usecases")

        bad_payloads = [
            {"trapdoor": "deadbeef"},
            {"privateKey": "x"},
            {"sk": "x"},
            {"cscid": "123"},
            {"identityHash": "ab" * 32},
            {"nested": {"a": 1}},
            {"pem": "-----BEGIN PRIVATE KEY-----"},
        ]
        for payload in bad_payloads:
            try:
                uc.OpenTicketUseCase(c.coord_ctx).execute(
                    requester="TP", responder="AP", kind="lineage_proof",
                    payload=payload, case_ref="case-x")
            except NonPublic:
                continue
            raise AssertionError(f"卡口放过了 {payload!r}")

        # 正常载荷仍然能过
        t = uc.OpenTicketUseCase(c.coord_ctx).execute(
            requester="TP", responder="AP", kind="lineage_proof",
            payload={"did": "did:tpaa:abc"}, case_ref="case-x")
        assert t.state.value == "pending"


def test_coordination_blocks_self_answer():
    with chain_env() as c:
        uc = load_service("coordination", "domain.usecases")
        ChannelError = load_service("coordination", "domain.entities").ChannelError

        t = uc.OpenTicketUseCase(c.coord_ctx).execute(
            requester="TP", responder="AP", kind="lineage_proof",
            payload={"did": "did:tpaa:abc"}, case_ref="case-x")

        try:
            uc.AnswerTicketUseCase(c.coord_ctx).execute(
                ticket_id=t.ticket_id, responder="TP", answer={"parentDid": ""})
        except ChannelError:
            pass
        else:
            raise AssertionError("TP 竟然能替 AP 答复 —— 通道会变成自问自答")

        uc.AnswerTicketUseCase(c.coord_ctx).execute(
            ticket_id=t.ticket_id, responder="AP", answer={"parentDid": ""})

        # 重复答复必须拒绝：取证时无法区分哪一份是真的
        try:
            uc.AnswerTicketUseCase(c.coord_ctx).execute(
                ticket_id=t.ticket_id, responder="AP", answer={"parentDid": "x"})
        except ChannelError:
            pass
        else:
            raise AssertionError("同一张工单被答复了两次")


# ---------------------------------------------------------------------------
# 4. 审计链不可篡改
# ---------------------------------------------------------------------------


def test_audit_chain_detects_content_tampering():
    with chain_env() as c:
        rec = load_service("audit-service", "domain.usecases").RecordUseCase(c.audit_ctx)
        for i in range(4):
            rec.execute(kind="test.event", subject=f"s-{i}", payload={"i": i})

        verify = load_service("audit-service", "domain.usecases").VerifyChainUseCase(
            c.audit_ctx).execute()
        assert verify.ok is True

        path = Path(c.audit_ctx.ledger.store.path)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["entries"][1]["payload"]["i"] = 999          # 改内容
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        broken = load_service("audit-service", "domain.usecases").VerifyChainUseCase(
            c.audit_ctx).execute()
        assert broken.ok is False, "改了内容竟然没被发现"
        assert broken.broken_at == 2


def test_audit_chain_detects_insertion():
    with chain_env() as c:
        rec = load_service("audit-service", "domain.usecases").RecordUseCase(c.audit_ctx)
        for i in range(3):
            rec.execute(kind="test.event", subject=f"s-{i}", payload={"i": i})

        path = Path(c.audit_ctx.ledger.store.path)
        data = json.loads(path.read_text(encoding="utf-8"))
        fake = dict(data["entries"][1])
        fake["seq"] = 99
        fake["entryId"] = "ae-000099"
        data["entries"].insert(2, fake)                   # 插一条
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        broken = load_service("audit-service", "domain.usecases").VerifyChainUseCase(
            c.audit_ctx).execute()
        assert broken.ok is False, "插入条目竟然没被发现"


# ---------------------------------------------------------------------------
# 5. 吊销：案由必填、幂等、级联不漏
# ---------------------------------------------------------------------------


def test_revocation_requires_grounds():
    with chain_env() as c:
        root_did, _ = _seed(c)
        pol = load_service("policy-service", "domain.usecases")
        MissingGrounds = load_service("policy-service", "domain.entities").MissingGrounds

        try:
            pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
                root_did=root_did, case_ref="", reason="随便"))
        except MissingGrounds:
            pass
        else:
            raise AssertionError("没有案由的吊销令竟然被执行了")

        try:
            pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
                root_did=root_did, case_ref="case-1", reason=""))
        except MissingGrounds:
            pass
        else:
            raise AssertionError("没有理由的吊销令竟然被执行了")


def test_revocation_is_idempotent_and_cascades_through_registry_depth():
    """级联要一直走到头，哪怕本机没有那一层。

    ★ 这里直接往 did-service 登记了一个"孙体"，因为 agent-service 目前
      只允许主智能体派生（见下一个用例）。这条限制是刻意的，
      但**注册表这一层不能有同样的限制** —— 否则将来放开多级派生时，
      级联会悄悄只走一层，而那种漏洞在出事那天才会暴露。
    """
    with chain_env() as c:
        root_did, sub_did = _seed(c)
        grand = "did:tpaa:demo-grandchild"
        c.register(grand, parent=sub_did)

        pol = load_service("policy-service", "domain.usecases")
        first = pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
            root_did=root_did, case_ref="case-2", reason="测试级联"))
        assert set(first.revoked) == {root_did, sub_did, grand}, first.revoked

        second = pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
            root_did=root_did, case_ref="case-2", reason="测试级联"))
        assert second.revoked == [], "重复吊销应记为 already，而不是再撤销一次"
        assert set(second.already_revoked) == {root_did, sub_did, grand}

        # 注册表：三层全部 revoked，且非根节点记为 cascade
        assert c.did_ctx.registry.get(grand).revoke_source == "cascade"
        assert c.did_ctx.registry.get(grand).state.value == "revoked"

        # AP 侧：本机有的两只停了；孙体不在本机，必须如实报 not_local
        assert set(first.notified) == {root_did, sub_did}, first.notified
        for did in (root_did, sub_did):
            assert c.agent_ctx.agents.load_meta(did).state.value == "frozen", did


def test_agent_service_allows_derivation_only_from_primary():
    """钉住现有模型：只允许主智能体派生一层。

    这条不是"没实现多级"，而是刻意的：每多一层，追溯链就多一环，
    而"每一环都必须有人确认"的成本是线性增长的。
    真放开多级时，这个用例必须被改掉 —— 让它成为一次显式的决定。
    """
    with chain_env() as c:
        _, sub_did = _seed(c)
        IssueRejected = load_service("agent-service", "domain.usecases").IssueRejected
        ent = load_service("agent-service", "domain.entities")
        sel = ent.Selection(choices=(ent.ModuleChoice("summarize", "1.0.0"),))

        try:
            load_service("agent-service", "domain.usecases").DeriveSubAgentUseCase(
                c.agent_ctx).prepare(parent_did=sub_did, selection=sel, ttl_hours=24)
        except IssueRejected:
            return
        raise AssertionError("子体竟然被允许再派生子体 —— 与已定模型不符")


def test_lifecycle_sweeps_local_descendants_even_if_broadcast_misses_them():
    """广播只点名了主 DID，但本机还有一个子体 —— 必须一起停。

    这是整条链最容易漏的一处：policy 的 revoked 列表来自 did-service，
    而 did-service 可能因为注册延迟少一个。本地扫以磁盘事实为准。
    """
    with chain_env() as c:
        root_did, sub_did = _seed(c)
        life = load_service("lifecycle-service", "domain.usecases")
        life_ent = load_service("lifecycle-service", "domain.entities")

        out = life.HandleRevocationUseCase(c.life_ctx).execute(
            life_ent.RevocationNotice(root_did=root_did, revoked=[root_did],
                                      case_ref="case-3", reason="广播漏了子体"))
        assert root_did in out.stopped
        assert sub_did in out.stopped, "子体不在广播里，但本机有 —— 必须一起停"
        assert c.agent_ctx.agents.load_meta(sub_did).state.value == "frozen"


def test_lifecycle_refuses_notice_without_case_ref():
    with chain_env() as c:
        root_did, _ = _seed(c)
        life = load_service("lifecycle-service", "domain.usecases")
        ent = load_service("lifecycle-service", "domain.entities")

        try:
            life.HandleRevocationUseCase(c.life_ctx).execute(
                ent.RevocationNotice(root_did=root_did, revoked=[root_did],
                                     case_ref="", reason="无案由"))
        except ent.LifecycleError:
            pass
        else:
            raise AssertionError("无案由的吊销通知竟然被执行了 —— 广播不能只信上游")


# ---------------------------------------------------------------------------
# 6. 揭露的自证：CSCID 被换过就查得出来
# ---------------------------------------------------------------------------


def test_disclosure_detects_swapped_cscid():
    with chain_env() as c:
        root_did, sub_did = _seed(c)
        sup = load_service("supervision-service", "domain.usecases")
        case_id = _case(c, sub_did)
        sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
            case_id=case_id, reviewers=["a", "b"]))

        inv = sup.InvestigateUseCase(c.sup_ctx).execute(
            case_id=case_id, requested_by="t")
        assist = load_service("lifecycle-service", "domain.usecases").AnswerAssistUseCase(
            c.life_ctx).execute(kind="lineage_proof", payload={"did": sub_did})
        load_service("coordination", "domain.usecases").AnswerTicketUseCase(
            c.coord_ctx).execute(ticket_id=inv.ticket_id, responder="AP",
                                 answer=assist.answer)
        sup.CollectProofUseCase(c.sup_ctx).execute(
            case_id=case_id, ticket_id=inv.ticket_id)

        # 把封存的 CSCID 换成另一个身份的 —— 模拟"封存之后被调换"
        import crypto.sdk

        other = identity_hash(b"another-person")
        forged = crypto.sdk.seal_identity(other, c.sup_key.public())
        rec = c.did_ctx.registry.get(sub_did)
        rec.cscid = str(forged)
        c.did_ctx.registry.put(rec)

        out = sup.DiscloseUseCase(c.sup_ctx).execute(
            case_id=case_id, requested_by="t")
        assert int(out.identity_hash, 16) != c.hid
        assert out.verified is False, "换了 CSCID 竟然还通过了 AF 复核"
        assert "AF 复核不成立" in out.verify_note


# ---------------------------------------------------------------------------
# 7. 启动自检
# ---------------------------------------------------------------------------


def test_did_service_never_holds_a_decryption_capable_key():
    """号码簿只该拿到公钥形态 —— 完整密钥出现在这里就是装配错了。"""
    with chain_env() as c:
        pub = c.did_ctx.supervision_pub
        assert type(pub).__name__ == "SupervisionPublic"
        try:
            pub.open(12345)
        except PermissionError:
            pass
        else:
            raise AssertionError("did-service 手里的键竟然能解密")


def test_supervision_refuses_degraded_key():
    """把监管密钥序列化一圈（降级成公钥），启动自检必须拦住。"""
    import pickle

    with chain_env() as c:
        degraded = pickle.loads(pickle.dumps(c.sup_key))
        w = load_service("supervision-service", "infra.wiring")
        try:
            w.build_context(
                db_path=str(c.root / "cases2.json"),
                directory=c.sup_ctx.directory, channel=c.sup_ctx.channel,
                storage=c.sup_ctx.storage, audit=c.sup_ctx.audit,
                key=degraded, clock=c.clock, tp_ch=c.sup_ctx.tp_ch)
        except w.ConfigError as exc:
            assert "降级" in str(exc), str(exc)
        else:
            raise AssertionError("降级的监管密钥竟然能启动 —— 它永远解不开 CSCID")

