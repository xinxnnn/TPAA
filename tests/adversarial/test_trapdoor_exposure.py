"""对抗测试 · 变色龙陷门的开口泄露（交接说明 §9.2）。

★ 本文件钉住的是一个**已知漏洞**，不是一条"攻击必须失败"的断言。

背景：
    CH(m, r) = H(m·G + r·cpk)，cpk = x·G。
    同一个哈希值若公开了两组开口 (m1, r1) / (m2, r2)，则
        m1 + r1·x ≡ m2 + r2·x  (mod N)
        x = (m1 − m2) / (r2 − r1)  (mod N)
    陷门 x 可被任何持有两组开口的人直接解出。

本方案里谁会持有两组开口：
    TP 在 issue 时得到 APM 为空的 PHC（开口 1），
    协查 / 交付时又会见到算法1 之后的 PHC（开口 2）。
    于是 **TP 可算出 AP 的陷门**，进而以 AP 的名义改写 APM ——
    "TP/AP 双域隔离、算法1 只有 AP 能做"在数学上不成立。

断言方向：
    当前代码下攻击**成功**，测试通过 = 漏洞仍在（如实记录现状）。
    修复后（换 key-exposure-free 的 CCH 构造或一次性 CH 密钥，需按说明书原式核定），
    应把 `_expect_exploitable` 改为 False，测试即转为"攻击必须失败"。
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import Parties, identity_hash  # noqa: E402

from crypto.phc import issue_phc, update_by_ap, update_by_tp, verify_phc  # noqa: E402
from crypto.primitives import N, point_mul, ser_point  # noqa: E402

# 修复落地后改为 False
_expect_exploitable = True

IDH = identity_hash()
TAU, CRF = 20261014, 555777


def _business_path():
    """走真实引擎路径：TP 签发 → TP 封 DID → AP 算法1。返回 TP 可见的两版 PHC。"""
    p = Parties()
    phc = issue_phc(
        tp_hsm=p.tp_hsm, ap_ch=p.ap_pub,
        identity_hash=IDH, tau=TAU, crf=CRF,
        tpm_time="2026-10-14T10:00:00", tpm_ecid="ecid-001",
        apid=ser_point(p.ap_pk),
    )
    phc = update_by_tp(phc, tp_hsm=p.tp_hsm, did="did:tpaa:primary:000001")
    tp_view_before = copy.deepcopy(phc)          # TP 签发/封印时手里的那一版
    final = update_by_ap(copy.deepcopy(phc), ap_hsm=p.ap_hsm,
                         cmi="ab" * 32, apm_time="2026-10-14T10:05:00")
    return p, tp_view_before, final


def _recover_trapdoor(before, after) -> int | None:
    """只用两版 PHC 的公开字段解 x。"""
    m1, r1 = before.apch_message(), before.proof_apch_r
    m2, r2 = after.apch_message(), after.proof_apch_r
    if (r2 - r1) % N == 0:
        return None
    return ((m1 - m2) * pow(r2 - r1, -1, N)) % N


def test_known_vuln_tp_recovers_ap_trapdoor_from_two_phc_versions() -> None:
    p, before, final = _business_path()
    assert before.proof_apch == final.proof_apch, "前提：算法1 保持 APCH 不变"

    x = _recover_trapdoor(before, final)
    exploitable = x is not None and point_mul(x) == p.ap_hsm.chameleon_cpk()

    if _expect_exploitable:
        assert exploitable, (
            "陷门已无法从两组开口还原 —— 若这是修复的结果，"
            "请把 _expect_exploitable 改为 False")
    else:
        assert not exploitable, "TP 仍能从两版 PHC 还原 AP 的陷门"


def test_known_vuln_tp_forges_apm_with_recovered_trapdoor() -> None:
    """拿到陷门后，TP 不经 AP 改写 CMI，凭证仍校验通过。"""
    p, before, final = _business_path()
    x = _recover_trapdoor(before, final)
    if x is None or point_mul(x) != p.ap_hsm.chameleon_cpk():
        assert not _expect_exploitable, "预期可利用，但未能还原陷门"
        return

    forged = copy.deepcopy(final)
    old_m, old_r = forged.apch_message(), forged.proof_apch_r
    forged.apm_cmi = "ee" * 32                    # 恶意配置
    # APproof 是 AP 的 Schnorr 签名，TP 无法重签 —— 保留原值
    new_m = forged.apch_message()
    forged.proof_apch_r = (old_r + (old_m - new_m) * pow(x, -1, N)) % N

    errs = verify_phc(
        forged, tp_pk=p.tp_pk, ap_pk=p.ap_pk,
        tp_ch=p.tp_pub, ap_ch=p.ap_pub,
        identity_hash=IDH, tau=TAU, crf=CRF,
    )
    assert forged.proof_apch == final.proof_apch, "陷门有效：APCH 碰撞成立"
    # ★ 当前唯一挡住伪造的是 APproof（AP 的 Schnorr 签名），不是变色龙哈希。
    #   也就是说"APCH 只有 AP 能改"这条已经不成立，安全性退化成单靠 AP 签名。
    #   若有一天 APproof 不再覆盖 APM（或被移出校验），伪造会直接通过。
    assert errs == ["AP 背书 APA.proof 无效"], f"预期只剩 APproof 一道防线，实际：{errs}"
