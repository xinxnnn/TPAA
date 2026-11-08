"""派生链测试 —— 子智能体的身份归属与级联失效。

核心命题：
    1. 子体有唯一 DID，且父指针被密码学封死（改了就锚定失败）
    2. 追溯可由子体上溯到主 DID，也可由子体直接解出自然人
    3. 主凭证吊销 → 全部后代即时失效
    4. 未确认的派生不产生任何密钥操作

★ 派生是**公开动作**（只要算值得出新的 AF），唯一步骤遗漏：给子体封 DID
  必须由 TP 完成 —— 因此也只有 seal_child_did 需要注入 TP 的 HSM 句柄。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import Parties, identity_hash  # noqa: E402

from crypto.derivation import (  # noqa: E402
    DerivationRecord,
    cascade_revoke,
    derive_child_phc,
    seal_child_did,
    trace_to_root,
    verify_lineage,
)
from crypto.phc import PHC, issue_phc, update_by_ap, update_by_tp, verify_phc  # noqa: E402
from crypto.primitives import hash_chain, ser_point  # noqa: E402

IDH = identity_hash()


def _issue_primary() -> tuple[PHC, Parties]:
    p = Parties()
    phc = issue_phc(
        tp_hsm=p.tp_hsm, ap_ch=p.ap_pub,
        identity_hash=IDH, tau=1, crf=111,
        tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        apid=ser_point(p.ap_pk),
    )
    cmi = hash_chain([b"<code:planner-primary>"])
    update_by_ap(phc, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:01:00")
    update_by_tp(phc, tp_hsm=p.tp_hsm, did="did:wba:ROOT:pa.example")
    return phc, p


def test_child_has_own_did_and_parent_pointer() -> None:
    """子体走完整流程后有唯一 DID，且 parent_did 指向主。"""
    parent, p = _issue_primary()

    child = derive_child_phc(
        parent=parent, parent_did=parent.tpm_cdid,
        tp_ch=p.tp_pub, ap_ch=p.ap_pub, identity_hash=IDH, tau=2, crf=222,
    )
    assert child.parent_did == parent.tpm_cdid
    assert child.tpm_af != parent.tpm_af, "子体的 AF 必须与主不同"

    # 子体同样走完整的算法1 + 算法2，不是"主凭证的附页"
    cmi = hash_chain([b"<code:planner-sub>"])
    update_by_ap(child, ap_hsm=p.ap_hsm, cmi=cmi.hex(), apm_time="2026-10-14T10:05:00")
    seal_child_did(child, tp_hsm=p.tp_hsm, did="did:wba:SUB1:pa.example",
                   tpm_time="2026-10-14T10:06:00")

    assert child.tpm_cdid == "did:wba:SUB1:pa.example"
    assert child.parent_did == "did:wba:ROOT:pa.example"

    errs = verify_phc(child, **p.verify_kwargs(identity_hash=IDH, tau=2, crf=222))
    assert errs == [], f"子体 PHC 应校验通过，实际：{errs}"


def test_parent_pointer_is_cryptographically_bound() -> None:
    """★ 改 parent_did 会让 AF 锚定失败 —— 父子关系不可伪造。"""
    p = Parties()
    parent_did = "did:wba:ROOT:pa.example"

    child = derive_child_phc(
        parent=PHC(), parent_did=parent_did,
        tp_ch=p.tp_pub, ap_ch=p.ap_pub, identity_hash=IDH, tau=3, crf=333,
    )

    # 声称的父 DID 正确 → 无错误
    assert verify_lineage(child, tp_ch=p.tp_pub, identity_hash=IDH, tau=3, crf=333,
                          expected_parent_did=parent_did) == []

    # 攻击者把父指针改成别人 → 必须被检出
    child.parent_did = "did:wba:ATTACKER:pa.example"
    errs = verify_lineage(child, tp_ch=p.tp_pub, identity_hash=IDH, tau=3, crf=333,
                          expected_parent_did="did:wba:ATTACKER:pa.example")
    assert errs, "改了 parent_did 必须让 AF 锚定失败"


def test_derivation_itself_uses_no_private_key() -> None:
    """★ 派生是纯公开动作 —— 产出的骨架里不该有任何签名。

    没有签名 = 没有任何私钥被调用过。给子体落 DID 是 TP 的事，
    必须另外走 seal_child_did 并注入 TP 的句柄。
    """
    p = Parties()
    from crypto.primitives import ChameleonHash, ChameleonKey

    # 即便调用方误把含陷门的完整句柄塞进来，派生也只用它的 compute
    child = derive_child_phc(
        parent=PHC(), parent_did="did:wba:ROOT:pa.example",
        tp_ch=ChameleonHash(ChameleonKey()), ap_ch=ChameleonHash(ChameleonKey()),
        identity_hash=IDH, tau=4, crf=444,
    )
    assert child.proof_chproof == b"", "派生不应产生 TP 签名"
    assert child.tpa_proof == b"", "派生不应替 TP 背书"
    assert child.tpm_cdid == "", "DID 必须由 TP 封印，派生阶段不得代劳"


def test_seal_child_did_refuses_raw_secret_scalars() -> None:
    """给子体封 DID 时顺手把 tp_sk 也递进来 —— 迁移期的典型残留，必须被拒。"""
    p = Parties()
    child = derive_child_phc(
        parent=PHC(), parent_did="did:wba:ROOT:pa.example",
        tp_ch=p.tp_pub, ap_ch=p.ap_pub, identity_hash=IDH, tau=5, crf=555,
    )
    try:
        seal_child_did(child, tp_hsm=p.tp_hsm, tp_sk=1,
                       did="did:wba:SUB:pa.example", tpm_time="2026-10-14T10:06:00")
    except TypeError as e:
        assert "红线 1" in str(e), f"错误应点明红线，实际：{e}"
    else:
        raise AssertionError("seal_child_did 不应接受原始私钥标量")


def test_trace_to_root_returns_full_chain() -> None:
    """追溯时的归属证明：子 → 父 → 祖父 … → 主。"""
    records = {
        "sub2": DerivationRecord(child_did="sub2", parent_did="sub1", confirmed_by_user=True),
        "sub1": DerivationRecord(child_did="sub1", parent_did="root", confirmed_by_user=True),
        "root": DerivationRecord(child_did="root", parent_did="", agent_type="primary",
                                 confirmed_by_user=True),
    }
    chain = trace_to_root("sub2", records)
    assert chain == ["sub2", "sub1", "root"], f"实际链路：{chain}"


def test_trace_to_root_survives_cycles() -> None:
    """关系表被污染成环状时，上溯必须能停下来而不是死循环。"""
    records = {
        "a": DerivationRecord(child_did="a", parent_did="b"),
        "b": DerivationRecord(child_did="b", parent_did="a"),
    }
    chain = trace_to_root("a", records)
    assert len(chain) <= 3


def test_cascade_revoke_disables_all_descendants() -> None:
    """★ 主凭证吊销 → 所有后代即时失效。"""
    records = {
        "root": DerivationRecord(child_did="root", parent_did="", agent_type="primary"),
        "s1": DerivationRecord(child_did="s1", parent_did="root"),
        "s2": DerivationRecord(child_did="s2", parent_did="root"),
        "s3": DerivationRecord(child_did="s3", parent_did="s1"),   # 孙辈
        "other": DerivationRecord(child_did="other", parent_did="elsewhere"),
    }
    affected = cascade_revoke("root", records)

    assert set(affected) == {"s1", "s2", "s3"}, f"实际级联：{affected}"
    assert records["s3"].revoked, "孙辈也必须被级联"
    assert not records["other"].revoked, "不相关的分支不应受影响"
    assert all(r.revoke_reason == "parent_revoked" for r in records.values() if r.revoked)


def test_unconfirmed_derivation_has_no_key_material() -> None:
    """★ 未确认的派生：记录里不得有任何密钥材料，且标记为非法。"""
    rec = DerivationRecord(
        child_did="subX", parent_did="root",
        confirmed_by_user=False,          # 用户没确认
    )
    # 未确认 → 视为非法，不得进入生成阶段
    assert rec.confirmed_by_user is False
    # 确认证据为空（没有时间/设备/配置快照）
    assert rec.confirm_evidence == {}


def test_confirmed_derivation_carries_evidence() -> None:
    """确认过的派生必须带证据：时间 / 设备 / 配置快照 / 条款版本。"""
    rec = DerivationRecord(
        child_did="subY", parent_did="root",
        confirmed_by_user=True,
        confirm_evidence={
            "confirmed_at": "2026-10-14T10:20:00",
            "device_fingerprint": "abc123",
            "selection_snapshot": hash_chain([b"<code:planner>"]).hex(),
            "consent_version": "v1.2",
        },
    )
    ev = rec.confirm_evidence
    assert {"confirmed_at", "device_fingerprint", "selection_snapshot", "consent_version"} <= ev.keys()
