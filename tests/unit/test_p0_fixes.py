"""P0 修复的回归用例。

    0.3  DID 发号状态落盘：重启后不撞号
    0.4  生产装配必须注入 HSM 种子：缺了拒绝启动；同一种子重启后旧 PHC 仍可验
    0.5  TP 替身只收 AP 公钥材料：给它 HSM 本体或含陷门句柄当场拒绝
    0.6  派生确认：必须 prepare 过、只能确认一次、令牌绑定父体、并发只核销一次
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import load_service  # noqa: E402

import crypto.sdk  # noqa: E402
from services.ipfs.storage_service.app import StorageService  # noqa: E402


_MODS = {"engine.py": b"def run(text):\n    return text[:80]\n"}
_HID = int("ab" * 32, 16)


def _ctx(root: str, *, tp_hsm=None, ap_hsm=None):
    infra = load_service("agent-service", "infra.wiring")
    ctx = infra.build_context(
        config=infra.InfraConfig(
            store_root=root,
            index_key_hex=("11" * 32), ecid_key_hex=("22" * 32),
        ),
        tp_hsm=tp_hsm or crypto.sdk.make_demo_hsm(domain="TP"),
        ap_hsm=ap_hsm or crypto.sdk.make_demo_hsm(domain="AP"),
        storage=StorageService(),
    )
    for mid in ("summarize", "translate"):
        if not (ctx.layout.module_dir(mid, "1.0.0")).exists():
            ctx.modules.publish(mid, "1.0.0", _MODS, description=mid)
    return ctx


def _issue(ctx, mid="summarize"):
    uc = load_service("agent-service", "domain.usecases")
    ent = load_service("agent-service", "domain.entities")
    sel = ent.Selection(choices=(ent.ModuleChoice(mid, "1.0.0"),))
    return uc.IssueAgentUseCase(ctx).execute(uc.IssueCommand(
        identity_hash=_HID, tau=1, crf=1, selection=sel))


def _raises(exc_type, fn, needle: str = ""):
    try:
        fn()
    except exc_type as exc:
        assert needle in str(exc), f"错误信息里没有 {needle!r}：{exc}"
        return
    raise AssertionError(f"预期抛出 {exc_type.__name__}")


# ---------------------------------------------------------------------------
# 0.3 / 0.4
# ---------------------------------------------------------------------------


def test_did_sequence_survives_restart_and_old_phc_still_verifies() -> None:
    tp = crypto.sdk.make_demo_hsm(domain="TP")
    ap = crypto.sdk.make_demo_hsm(domain="AP")
    with tempfile.TemporaryDirectory() as d:
        first = _issue(_ctx(d, tp_hsm=tp, ap_hsm=ap), "summarize")
        # "重启"：新建上下文，同一存储根、同一对密钥
        ctx2 = _ctx(d, tp_hsm=tp, ap_hsm=ap)
        second = _issue(ctx2, "translate")
        assert first.did != second.did, f"重启后撞号：{first.did}"
        ok = ctx2.capability.verify_phc(first.phc_json, identity_hash=_HID, tau=1, crf=1)
        assert ok.ok, ok.errors


def test_corrupt_did_sequence_refuses_to_start() -> None:
    cap = load_service("agent-service", "infra.capability")
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "did-seq.json").write_text("{not json", encoding="utf-8")
        ap = crypto.sdk.make_demo_hsm(domain="AP")
        _raises(cap.CapabilityError, lambda: cap.LocalTpAuthority(
            tp_hsm=crypto.sdk.make_demo_hsm(domain="TP"),
            ap_pk=ap.pubkey(), ap_ch=ap.public_chameleon(),
            ecid_key=b"\x00" * 32, state_dir=d), "发号状态损坏")


def test_missing_hsm_seed_refuses_to_start() -> None:
    infra = load_service("agent-service", "infra.wiring")
    ctxmod = load_service("agent-service", "domain.services.context")
    _raises(ctxmod.ConfigError, lambda: infra.load_hsm_seed({}), "TPAA_HSM_SEED")


def test_hsm_seed_gives_same_keys_across_loads() -> None:
    infra = load_service("agent-service", "infra.wiring")
    seed = {"tp": {"schnorr_sk": "0a" * 16, "chameleon_sk": "0b" * 16},
            "ap": {"schnorr_sk": "0c" * 16, "chameleon_sk": "0d" * 16}}
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "seed.json"
        p.write_text(json.dumps(seed), encoding="utf-8")
        a_tp, a_ap = infra.load_hsm_seed({"TPAA_HSM_SEED": str(p)})
        b_tp, b_ap = infra.load_hsm_seed({"TPAA_HSM_SEED": str(p)})
        assert a_tp.pubkey() == b_tp.pubkey() and a_ap.pubkey() == b_ap.pubkey()
        assert a_tp.domain == "TP" and a_ap.domain == "AP"

        p.write_text(json.dumps({"tp": seed["tp"]}), encoding="utf-8")
        ctxmod = load_service("agent-service", "domain.services.context")
        _raises(ctxmod.ConfigError,
                lambda: infra.load_hsm_seed({"TPAA_HSM_SEED": str(p)}), "ap.")


# ---------------------------------------------------------------------------
# 0.5
# ---------------------------------------------------------------------------


def test_tp_authority_rejects_ap_hsm_or_trapdoor_handle() -> None:
    cap = load_service("agent-service", "infra.capability")
    tp = crypto.sdk.make_demo_hsm(domain="TP")
    ap = crypto.sdk.make_demo_hsm(domain="AP")

    # 把 HSM 本体当 ap_ch 塞进来
    _raises(cap.CapabilityError, lambda: cap.LocalTpAuthority(
        tp_hsm=tp, ap_pk=ap.pubkey(), ap_ch=ap, ecid_key=b"\x00" * 32), "公钥材料")

    # 含陷门的 ChameleonHash（HSM 内部对象）
    _raises(PermissionError, lambda: cap.LocalTpAuthority(
        tp_hsm=tp, ap_pk=ap.pubkey(), ap_ch=ap._chameleon_hash,   # noqa: SLF001
        ecid_key=b"\x00" * 32), "红线 1")


def test_wired_tp_authority_holds_no_ap_trapdoor() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx = _ctx(d)
        tp_side = ctx.capability._tp                     # noqa: SLF001
        held = [v for v in vars(tp_side).values()
                if callable(getattr(v, "has_trapdoor", None)) and v.has_trapdoor()]
        assert held == [], f"TP 替身持有含陷门对象：{held}"
        assert not any(getattr(v, "domain", None) == "AP" for v in vars(tp_side).values())


# ---------------------------------------------------------------------------
# 0.6
# ---------------------------------------------------------------------------


def _derive_kit(d: str):
    ctx = _ctx(d)
    parent = _issue(ctx).did
    uc = load_service("agent-service", "domain.usecases")
    ent = load_service("agent-service", "domain.entities")
    sel = ent.Selection(choices=(ent.ModuleChoice("translate", "1.0.0"),))
    return ctx, parent, uc, ent, sel


def _ticket_like(uc, t, **over):
    base = dict(ticket_id=t.ticket_id, parent_did=t.parent_did,
                selection_digest=t.selection_digest, ttl_hours=t.ttl_hours,
                created_at=t.created_at)
    base.update(over)
    return uc.ConfirmationTicket(**base)


def test_confirm_requires_prepared_ticket() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx, parent, uc, ent, sel = _derive_kit(d)
        forged = uc.ConfirmationTicket(
            ticket_id="tkt-made-up", parent_did=parent,
            selection_digest=ent.digest_selection(sel), ttl_hours=24, created_at="")
        _raises(ent.NotConfirmed,
                lambda: uc.DeriveSubAgentUseCase(ctx).confirm(token="cfm-x", ticket=forged),
                "prepare")


def test_ticket_id_is_not_derivable_from_selection() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx, parent, uc, ent, sel = _derive_kit(d)
        a = uc.DeriveSubAgentUseCase(ctx).prepare(parent_did=parent, selection=sel, ttl_hours=24)
        b = uc.DeriveSubAgentUseCase(ctx).prepare(parent_did=parent, selection=sel, ttl_hours=24)
        assert a.ticket_id != b.ticket_id
        assert ent.digest_selection(sel)[:16] not in a.ticket_id


def test_confirm_rejects_tampered_fields_and_double_confirm() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx, parent, uc, ent, sel = _derive_kit(d)
        d_uc = uc.DeriveSubAgentUseCase(ctx)
        t = d_uc.prepare(parent_did=parent, selection=sel, ttl_hours=24)

        _raises(ent.NotConfirmed, lambda: d_uc.confirm(
            token="cfm-1", ticket=_ticket_like(uc, t, ttl_hours=720)), "不一致")
        _raises(ent.NotConfirmed, lambda: d_uc.confirm(
            token="cfm-2", ticket=_ticket_like(uc, t, parent_did="did:tpaa:primary:999999")),
            "不一致")

        d_uc.confirm(token="cfm-ok", ticket=_ticket_like(uc, t))
        _raises(ent.NotConfirmed, lambda: d_uc.confirm(
            token="cfm-again", ticket=_ticket_like(uc, t)), "已确认")


def test_token_is_bound_to_its_parent() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx, parent_a, uc, ent, sel = _derive_kit(d)
        parent_b = _issue(ctx, "translate").did
        d_uc = uc.DeriveSubAgentUseCase(ctx)
        t = d_uc.prepare(parent_did=parent_a, selection=sel, ttl_hours=24)
        tok = d_uc.confirm(token="cfm-a", ticket=_ticket_like(uc, t))

        _raises(ent.NotConfirmed, lambda: d_uc.execute(ent.ChildRequest(
            parent_did=parent_b, selection=sel, ttl_hours=24,
            confirmation=d_uc.load_ticket(tok.token))), "父体")


def test_concurrent_consume_succeeds_once() -> None:
    with tempfile.TemporaryDirectory() as d:
        ctx, parent, uc, ent, sel = _derive_kit(d)
        d_uc = uc.DeriveSubAgentUseCase(ctx)
        t = d_uc.prepare(parent_did=parent, selection=sel, ttl_hours=24)
        tok = d_uc.confirm(token="cfm-race", ticket=_ticket_like(uc, t))

        wins: list[bool] = []
        barrier = threading.Barrier(8)

        def go():
            barrier.wait()
            try:
                d_uc._consume_ticket(tok.token)          # noqa: SLF001
                wins.append(True)
            except ent.NotConfirmed:
                wins.append(False)

        ts = [threading.Thread(target=go) for _ in range(8)]
        for th in ts:
            th.start()
        for th in ts:
            th.join()
        assert wins.count(True) == 1, f"并发核销成功 {wins.count(True)} 次"


__all__ = [n for n in dir() if n.startswith("test_")]
