"""tpaa_v1 测试夹具：按说明书顺序走一遍 G1 → D6，留下每一步的中间值。

单元测试与对抗测试共用这一份，避免两边各装一套、悄悄少接一步。
监管 Paillier 密钥生成慢，模块级只生成一次。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import crypto.sdk  # noqa: E402

v1 = crypto.sdk.v1
HID = int.from_bytes(bytes.fromhex("5a" * 32), "big")
OWNER = "user-pk-fpr:demo"          # 已认证的用户标识（协议层负责认证）
MODULES = [("summarize", "1.0.0", "aa" * 32), ("translate", "1.0.0", "bb" * 32)]


@lru_cache(maxsize=1)
def sup_key():
    return crypto.sdk.make_supervision_key(bits=2048)


@dataclass
class Flow:
    tp: object
    ap: object
    sup: object
    tp_nonce: str
    ap_nonce: str
    r0: int                 # 用户在 G1 自选
    af_g1: object           # AfState
    af_g2: object           # TP 重绑后（x_t = X(IRF)）
    af_d4: object           # AP 重绑后（x_a = X(CMI)）
    irf: int
    s_ap: int
    rf: int
    cmi: str
    issued: object          # G3 输出（含 r_tp / r_ap）
    phc_d4: object
    r_ap1: int
    phc_d6: object
    r_tp1: int


def run(*, tp=None, ap=None, hid: int = HID, owner: str = OWNER) -> Flow:
    tp = tp or v1.make_demo_hsm(domain="TP")
    ap = ap or v1.make_demo_hsm(domain="AP")
    sup = sup_key()
    pub = sup.public()

    # 前置：用户向 TP / AP 各取一个本凭证专用的陷门公钥（errata E1）
    tp_nonce, t_pub = tp.allocate_slot(owner)
    ap_nonce, a_pub = ap.allocate_slot(owner)

    # G1（用户）
    r0 = v1.rand_exp()
    af_g1 = v1.commit_af(hid=hid, a_pub=a_pub, t_pub=t_pub, r=r0)

    # G2（TP）：IRF，再把 IRF 绑进 AF
    irf = v1.compute_irf(hid, pub)
    af_g2 = v1.rebind_af(af_g1, hsm=tp, hid=hid, nonce=tp_nonce, owner=owner,
                         kind="IRF", value=irf)
    ecid0 = v1.seal_ecid("bafy-demo-cid", pub)

    # G3（TP）
    issued = v1.issue_phc(tp_hsm=tp, ap_ch=ap.public_chameleon(), ap_pk=ap.pubkey(),
                          af=af_g2.af, ecid=format(ecid0, "x"), time="2026-10-14T10:00:00")

    # D4（AP）：CMI → 算法1 → AF 重绑 → s_ap / RF
    cmi = v1.hcgen(MODULES, hid)
    phc_d4, r_ap1 = v1.algorithm1(issued.phc, ap_hsm=ap, r_ap=issued.r_ap,
                                  cmi=cmi, time="2026-10-14T10:05:00")
    af_d4 = v1.rebind_af(af_g2, hsm=ap, hid=hid, nonce=ap_nonce, owner=owner,
                         kind="CMI", value=cmi)
    s_ap = v1.compute_s_ap(ap, af_d4.af)
    rf = v1.compute_rf(irf, s_ap, pub)

    # D6（TP）：算法2 写 CDID，并按式 6 重封 ECID（errata E5）
    mask = v1.ecid_mask(tp, rf, pub.n)
    ecid1 = v1.seal_ecid("bafy-demo-cid", pub, mask=mask)
    phc_d6, r_tp1 = v1.algorithm2(phc_d4, tp_hsm=tp, r_tp=issued.r_tp,
                                  cdid="did:wba:<CSCID>:tp.example:ap.example",
                                  time="2026-10-14T10:10:00", ecid=format(ecid1, "x"))
    return Flow(tp=tp, ap=ap, sup=sup, tp_nonce=tp_nonce, ap_nonce=ap_nonce, r0=r0,
                af_g1=af_g1, af_g2=af_g2, af_d4=af_d4, irf=irf, s_ap=s_ap, rf=rf, cmi=cmi,
                issued=issued, phc_d4=phc_d4, r_ap1=r_ap1, phc_d6=phc_d6, r_tp1=r_tp1)


def pub_keys(f: Flow) -> dict:
    return {"tp_pk": f.tp.pubkey(), "ap_pk": f.ap.pubkey()}


__all__ = ["Flow", "run", "pub_keys", "sup_key", "v1", "HID", "OWNER", "MODULES"]
