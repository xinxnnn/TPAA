"""追溯链演示：举报 → 立案 → 协查 → 揭露 → 取证 → 吊销 → 停运。

    python demos/personal_agent/demo_trace.py

不需要任何第三方依赖（不起 HTTP），全部走领域层。
要验 HTTP 接缝的，看 tests/integration/test_trace_api.py。

★ 这个脚本刻意把**每一次被拒绝**也打印出来。
  因为对追溯来说，"谁能查、查到什么程度"比"能不能查"更重要 ——
  一条只会演示成功路径的 demo，会让人误以为这套东西是"想查就查"。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from harness import TraceChain, load_service  # noqa: E402

LINE = "=" * 72


def step(t: str) -> None:
    print(f"\n{LINE}\n  {t}\n{LINE}")


def ok(label: str, cond: bool, extra: str = "") -> None:
    print(f"  [{'OK  ' if cond else 'FAIL'}] {label}{('   ' + extra) if extra else ''}")
    if not cond:
        raise AssertionError(label)


def refused(label: str, fn) -> None:
    """期待一次拒绝；没被拒反而是问题。"""
    try:
        fn()
    except Exception as exc:                                # noqa: BLE001
        print(f"  [拒  ] {label}  ←  {type(exc).__name__}: {str(exc)[:60]}")
        return
    raise AssertionError(f"{label} 竟然被放行了")


def main() -> int:
    c = TraceChain()
    sup = load_service("supervision-service", "domain.usecases")
    life = load_service("lifecycle-service", "domain.usecases")
    coord = load_service("coordination", "domain.usecases")
    pol = load_service("policy-service", "domain.usecases")
    aud = load_service("audit-service", "domain.usecases")
    did = load_service("did-service", "domain.usecases")

    # ---------------------------------------------------------------- 前情
    step("0. 前情：一位自然人，一只主智能体、一只子智能体")

    root_did, _ = c.issue_primary()
    ecid = c.g2_envelope()
    c.register(root_did, ecid=ecid)
    sub_did, sub_phc = c.derive_child(root_did)
    c.register(sub_did, parent=root_did, ecid=ecid)

    print(f"  主 DID   {root_did}")
    print(f"  子 DID   {sub_did}")
    ok("子体的 PHC 里封着父指针", sub_phc.get("parentDid") == root_did)

    lin = did.TraceLineageUseCase(c.did_ctx).execute(sub_did)
    ok("注册表能上溯到根", lin.chain == [sub_did, root_did], str(lin.chain))

    # 号码簿里只有密文；能开它的钥匙在监管域
    rec = c.did_ctx.registry.get(sub_did)
    ok("CSCID 是密文（不是 H(ID)）",
       rec.cscid and int(rec.cscid) != c.hid)
    refused("拿号码簿手里的公钥形态去解密",
            lambda: c.did_ctx.supervision_pub.open(int(rec.cscid)))

    # ---------------------------------------------------------------- 举报
    step("1. 举报：有人受害，指向那只子体")

    case = sup.ReportCaseUseCase(c.sup_ctx).execute(sup.ReportCommand(
        subject_did=sub_did, reporter="victim-001",
        allegation="该子体批量发送骚扰信息", evidence_ref="ipfs://evidence-1"))
    print(f"  案件 {case.case_id}  状态 {case.state}")
    ok("刚受理，还不能查", case.state == "reported")

    # ---- 闸门：这一步是整个系统的分界线 ----
    refused("未立案就发起协查",
            lambda: sup.InvestigateUseCase(c.sup_ctx).execute(
                case_id=case.case_id, requested_by="curious-officer"))
    refused("未立案就揭露身份",
            lambda: sup.DiscloseUseCase(c.sup_ctx).execute(
                case_id=case.case_id, requested_by="curious-officer"))
    refused("未立案就取证",
            lambda: sup.ForensicsUseCase(c.sup_ctx).execute(
                case_id=case.case_id, exported_by="curious-officer"))

    # ---------------------------------------------------------------- 立案
    step("2. 立案：两个人各自看过，都签了字")

    refused("同一个人签两次",
            lambda: sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
                case_id=case.case_id, reviewers=["reviewer-a", "reviewer-a"])))

    filed = sup.FileCaseUseCase(c.sup_ctx).execute(sup.FileCommand(
        case_id=case.case_id, reviewers=["reviewer-a", "reviewer-b"],
        note="证据充分，同意立案"))
    ok("双人复核通过", filed.state == "filed", str(filed.reviewers))

    # ---------------------------------------------------------------- 协查
    step("3. 协查：TP 只问一件事 —— 这条链的上一环是谁")

    inv = sup.InvestigateUseCase(c.sup_ctx).execute(
        case_id=case.case_id, requested_by="tp-officer")
    print(f"  工单 {inv.ticket_id}")
    ok("本地上溯已给出完整链", inv.lineage_chain == [sub_did, root_did],
       str(inv.lineage_chain))

    refused("TP 替 AP 答复自己的工单",
            lambda: coord.AnswerTicketUseCase(c.coord_ctx).execute(
                ticket_id=inv.ticket_id, responder="TP",
                answer={"parentDid": root_did}))

    assist = life.AnswerAssistUseCase(c.life_ctx).execute(
        kind="lineage_proof", payload={"did": sub_did})
    coord.AnswerTicketUseCase(c.coord_ctx).execute(
        ticket_id=inv.ticket_id, responder="AP", answer=assist.answer)
    ok("AP 答复只含公开材料",
       set(assist.answer) <= {"did", "parentDid", "agentType", "state",
                              "phcJson", "phcDigest"},
       str(sorted(assist.answer)))

    sup.CollectProofUseCase(c.sup_ctx).execute(
        case_id=case.case_id, ticket_id=inv.ticket_id)
    ok("AP 的 PHC 已留在案件里", bool(c.sup_ctx.cases.get(case.case_id).phc_json))

    # ---------------------------------------------------------------- 揭露
    step("4. 揭露：监管域用自己的钥匙打开 CSCID，再用 AF 自证")

    dis = sup.DiscloseUseCase(c.sup_ctx).execute(
        case_id=case.case_id, requested_by="tp-officer")
    print(f"  H(ID)  {dis.identity_hash[:16]}…")
    ok("还原出的就是举报里那个人", int(dis.identity_hash, 16) == c.hid)
    ok("AF 复算通过（凭证确实承诺这个身份）", dis.verified is True,
       dis.verify_note or "")

    # 只看过一眼不算数：号码簿那边留了痕
    log = c.did_ctx.registry.access_log()
    ok("CSCID 的取用被单独记了账", any(e.get("did") == sub_did for e in log),
       f"{len(log)} 条")

    # ---------------------------------------------------------------- 取证
    step("5. 取证：真去 IPFS 取一次，证明材料还在、没被换过")

    fx = sup.ForensicsUseCase(c.sup_ctx).execute(
        case_id=case.case_id, exported_by="tp-officer")
    print(f"  信封摘要 {fx.envelope_digest[:16]}…  {fx.envelope_bytes} 字节")
    ok("信封取回来了", fx.envelope_bytes > 0)
    ok("审计链自洽", fx.chain_verified is True, fx.verdict_reason)
    ok("案件已封存", fx.state == "sealed")

    # ---------------------------------------------------------------- 吊销
    step("6. 吊销：有案由才能下命令，一下就是整棵子树")

    refused("没有案由的吊销令",
            lambda: pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
                root_did=root_did, case_ref="", reason="看他不顺眼")))
    refused("没有理由的吊销令",
            lambda: pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
                root_did=root_did, case_ref=case.case_id, reason="")))

    out = pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
        root_did=root_did, case_ref=case.case_id,
        reason="主体名下智能体用于骚扰", issued_by="tp-officer"))
    print(f"  吊销令 {out.order_id}  状态 {out.state}")
    ok("主与子一起被撤", set(out.revoked) == {root_did, sub_did}, str(out.revoked))
    ok("AP 侧已收到通知", set(out.notified) == {root_did, sub_did}, str(out.notified))

    sub_rec = c.did_ctx.registry.get(sub_did)
    ok("子体记为级联吊销（不是直接吊销）",
       sub_rec.state.value == "revoked" and sub_rec.revoke_source == "cascade",
       sub_rec.revoke_source)

    for d in (root_did, sub_did):
        st = c.agent_ctx.agents.load_meta(d).state.value
        ok(f"本机实例已停运 {d.split(':')[-1]}", st == "frozen", st)

    # 幂等：再下一遍不会重复动作
    again = pol.RevokeUseCase(c.policy_ctx).execute(pol.RevokeCommand(
        root_did=root_did, case_ref=case.case_id, reason="重复下发"))
    ok("重复下发只记 already", again.revoked == [] and
       set(again.already_revoked) == {root_did, sub_did})

    # ---------------------------------------------------------------- 审计
    step("7. 审计：整条链可被第三方独立复算，且包里没有秘密")

    verify = aud.VerifyChainUseCase(c.audit_ctx).execute()
    ok("链完好", verify.ok is True, f"{verify.length} 条")

    bundle = aud.ExportCaseUseCase(c.audit_ctx).execute(
        case_ref=case.case_id, subjects=[root_did, sub_did])
    kinds = [e["kind"] for e in bundle.entries]
    print(f"  取证包 {len(bundle.entries)} 条记录  摘要 {bundle.bundle_digest[:16]}…")
    for k in ("case.filed", "case.investigating", "case.disclosed",
              "case.sealed", "policy.revoked"):
        ok(f"包内含 {k}", k in kinds)

    blob = str(bundle.to_json()).lower()
    ok("包里不含 H(ID)", format(c.hid, "x") not in blob)
    for word in ("trapdoor", "cscid", "privatekey"):
        ok(f"包里不含 {word}", word not in blob)

    # 篡改检测
    import json
    path = Path(c.audit_ctx.ledger.store.path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["entries"][0]["payload"]["tampered"] = True
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    broken = aud.VerifyChainUseCase(c.audit_ctx).execute()
    ok("改了一条记录就能被定位", broken.ok is False and broken.broken_at == 1,
       f"断在第 {broken.broken_at} 条")

    print(f"\n{LINE}\n  全链跑通。\n{LINE}")
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
