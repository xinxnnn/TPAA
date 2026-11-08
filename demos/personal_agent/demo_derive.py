"""派生链演示：主智能体 → 子智能体 → 追溯 → 级联吊销。

    python demos/personal_agent/demo_derive.py

不需要任何第三方依赖。

★ 演示脚本也要守红线：全程不出现原始密钥标量，
  TP / AP 各持自己的 HSM 句柄，跨域交换的只有 public_chameleon()。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crypto.derivation import (  # noqa: E402
    DerivationRecord,
    cascade_revoke,
    derive_child_phc,
    seal_child_did,
    trace_to_root,
    verify_lineage,
)
from crypto.hsm import SoftHSM  # noqa: E402
from crypto.phc import issue_phc, update_by_ap, update_by_tp, verify_phc  # noqa: E402
from crypto.primitives import hash_chain, ser_point  # noqa: E402

LINE = "=" * 72
IDH = int.from_bytes(hashlib.sha256(b"110101199003071234").digest(), "big")


def step(t: str) -> None:
    print(f"\n{LINE}\n  {t}\n{LINE}")


def ok(label: str, cond: bool, extra: str = "") -> None:
    print(f"  [{'OK  ' if cond else 'FAIL'}] {label}{('   ' + extra) if extra else ''}")
    if not cond:
        raise AssertionError(label)


# --- 两方各持自己的 HSM；跨域只交换公钥句柄 ---
tp_hsm = SoftHSM(domain="TP")
ap_hsm = SoftHSM(domain="AP")

tp_pub = tp_hsm.public_chameleon()      # 能算值、改不了内容
ap_pub = ap_hsm.public_chameleon()
tp_pk, ap_pk = tp_hsm.pubkey(), ap_hsm.pubkey()

records: dict[str, DerivationRecord] = {}

step("0 · 红线 1 的现场检查：跨域那份句柄改不了东西")
ok("交给对方的句柄里没有陷门", not ap_pub.has_trapdoor() and not tp_pub.has_trapdoor())

step("1 · 申领主智能体（G3 → 算法1 → 算法2）")

primary = issue_phc(
    tp_hsm=tp_hsm, ap_ch=ap_pub,
    identity_hash=IDH, tau=1, crf=111,
    tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
    apid=ser_point(ap_pk),
)
cmi0 = hash_chain([b"<code:planner-primary>"])
update_by_ap(primary, ap_hsm=ap_hsm, cmi=cmi0.hex(), apm_time="2026-10-14T10:01:00")
update_by_tp(primary, tp_hsm=tp_hsm, did="did:wba:ROOT:pa.example")

ok("主 PHC 校验通过",
   verify_phc(primary, tp_pk=tp_pk, ap_pk=ap_pk, tp_ch=tp_pub, ap_ch=ap_pub,
              identity_hash=IDH, tau=1, crf=111) == [])
print(f"  主 DID = {primary.tpm_cdid}")
records[primary.tpm_cdid] = DerivationRecord(
    child_did=primary.tpm_cdid, parent_did="", agent_type="primary", confirmed_by_user=True)

step("2 · 派生子智能体（同样的完整流程，唯一 DID）")

child = derive_child_phc(
    parent=primary, parent_did=primary.tpm_cdid,
    tp_ch=tp_pub, ap_ch=ap_pub, identity_hash=IDH, tau=2, crf=222,
)
cmi1 = hash_chain([b"<code:planner-sub>"])
update_by_ap(child, ap_hsm=ap_hsm, cmi=cmi1.hex(), apm_time="2026-10-14T10:05:00")
seal_child_did(child, tp_hsm=tp_hsm, did="did:wba:SUB1:pa.example",
               tpm_time="2026-10-14T10:06:00")

ok("子 PHC 校验通过（它自己也走完了算法1 + 算法2）",
   verify_phc(child, tp_pk=tp_pk, ap_pk=ap_pk, tp_ch=tp_pub, ap_ch=ap_pub,
              identity_hash=IDH, tau=2, crf=222) == [])
ok("子体有独立且唯一的 DID", child.tpm_cdid == "did:wba:SUB1:pa.example")
ok("子体的 AF 与主不同（不是复制品）", child.tpm_af != primary.tpm_af)
print(f"  子 DID  = {child.tpm_cdid}")
print(f"  父指针  = {child.parent_did}")

records[child.tpm_cdid] = DerivationRecord(
    child_did=child.tpm_cdid, parent_did=child.parent_did,
    confirmed_by_user=True,
    confirm_evidence={"confirmed_at": "2026-10-14T10:04:00", "consent_version": "v1.2"},
)

step("3 · 归属证明：由子体上溯到主")

chain = trace_to_root(child.tpm_cdid, records)
print(f"  链路 = {' → '.join(chain)}")
ok("上溯直达主 DID", chain[-1] == primary.tpm_cdid)

errs = verify_lineage(child, tp_ch=tp_pub, identity_hash=IDH, tau=2, crf=222,
                      expected_parent_did=primary.tpm_cdid)
ok("父指针被密码学封住（校验通过）", errs == [])

child.parent_did = "did:wba:ATTACKER:pa.example"
errs = verify_lineage(child, tp_ch=tp_pub, identity_hash=IDH, tau=2, crf=222,
                      expected_parent_did="did:wba:ATTACKER:pa.example")
ok("篡改父指针 → AF 锚定失败", bool(errs))
child.parent_did = primary.tpm_cdid

step("4 · 主凭证被吊销 → 级联失效")

affected = cascade_revoke(primary.tpm_cdid, records)
print(f"  被级联的子体：{affected}")
ok("子体即时失效", child.tpm_cdid in affected)
ok("只吊销主而放任子体运行 = 缺陷（这里没有发生）",
   all(records[d].revoked for d in affected))

print(f"\n{LINE}")
print("  派生链演示完成：唯一 DID · 父指针封死 · 可上溯 · 可级联")
print(LINE)
