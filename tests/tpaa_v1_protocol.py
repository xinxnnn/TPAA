"""tpaa_v1 端到端夹具：User / TP / AP / 审核 / IPFS 五方，按说明书 G1 → D6 → R1 → R2 走完。

每一步的线路密文与各方记录都留在 `Run` 上，负向测试从这里取材料去篡改、重放。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import crypto.sdk  # noqa: E402
from services.ipfs.storage_service.app import StorageService  # noqa: E402

from tpaa_v1_flow import sup_key  # noqa: E402

v1 = crypto.sdk.v1
U, T, A = v1.user, v1.tp, v1.ap

NOW = "2026-10-14T10:00:00"
EXP = "2026-10-14T11:00:00"
APP_ID = "app-1"        # D4Statement 绑定的申请号
REC_ID = "rec-1"        # D4 记录号，D6 一次性消费
PII = {"ID": "110101199003071234", "name": "张三", "phone": "13800000000"}
BI = {"iris": "iris-template-demo", "finger": "finger-template-demo"}
CMM = {"version": "cmm-2026-10",
       "categories": [{"id": "summarize", "options": ["1.0.0"]},
                      {"id": "translate", "options": ["1.0.0", "1.1.0"]}]}
DIGESTS = {("summarize", "1.0.0"): "aa" * 32, ("translate", "1.0.0"): "bb" * 32,
           ("translate", "1.1.0"): "cc" * 32}
SELECTION = [{"moduleId": "summarize", "version": "1.0.0"},
             {"moduleId": "translate", "version": "1.0.0"}]


def resolve(selection):
    """模块仓库查表：摘要取自仓库，不取自请求。"""
    try:
        return [(s["moduleId"], s["version"], DIGESTS[(s["moduleId"], s["version"])])
                for s in selection]
    except KeyError as e:
        raise v1.ProtocolError(f"模块不存在：{e}") from e


@dataclass
class Parties:
    tp: object = field(default_factory=lambda: v1.make_demo_hsm(domain="TP"))
    ap: object = field(default_factory=lambda: v1.make_demo_hsm(domain="AP"))
    user: object = field(default_factory=lambda: v1.make_demo_hsm(domain="USER"))
    review: object = field(default_factory=lambda: v1.make_demo_hsm(domain="REVIEW"))
    storage: object = field(default_factory=StorageService)

    @property
    def keys(self) -> dict:
        return {"tp_sign_pk": self.tp.pubkey(), "ap_sign_pk": self.ap.pubkey()}


@dataclass
class Run:
    p: Parties
    cr: dict = None
    pending: object = None
    opened: object = None
    approval: dict = None
    rr: dict = None
    trec: object = None
    cred: object = None
    ar: dict = None
    sess: object = None
    paci: dict = None
    par: dict = None
    arec: object = None
    verified: object = None
    didgr: dict = None
    final: dict = None
    trec2: object = None
    did: str = ""
    phc2: dict = None


def g1(p: Parties, *, user=None, pii=None) -> Run:
    user = user or p.user
    owner = v1.owner_of(user.pubkey())
    r = Run(p=p)
    r.cr, r.pending = U.g1_build_cr(
        user_hsm=user, pii=pii or PII, bi=BI, tp_enc_pk=p.tp.enc_pub(),
        tp_slot=p.tp.allocate_slot(owner), ap_slot=p.ap.allocate_slot(owner),
        ap_sign_pk=p.ap.pubkey(), request_id="cr-1", expires=EXP)
    return r


def through_g4(p: Parties) -> Run:
    sup = sup_key()
    r = g1(p)
    r.opened = T.tp_open_cr(tp_hsm=p.tp, cr_box=r.cr, now=NOW)
    r.approval = T.approve(reviewer_hsm=p.review, cr_digest=r.opened.cr_digest,
                           reviewers=["rev-a"], expires=EXP)
    r.rr, r.trec = T.tp_issue(tp_hsm=p.tp, opened=r.opened, approval=r.approval,
                              review_pk=p.review.pubkey(), sup_pub=sup.public(),
                              storage=p.storage, ap_ch=p.ap.public_chameleon(),
                              ap_sign_pk=p.ap.pubkey(), ap_enc_pk=p.ap.enc_pub(), now=NOW)
    r.cred = U.g4_accept_rr(user_hsm=p.user, rr_box=r.rr, pending=r.pending, **p.keys)
    return r


def full(p: Parties | None = None) -> Run:
    p = p or Parties()
    sup = sup_key()
    r = through_g4(p)

    r.ar = U.d1_build_ar(user_hsm=p.user, cred=r.cred, ap_enc_pk=p.ap.enc_pub(),
                         request_id="ar-1", expires=EXP)
    r.sess = A.ap_open_ar(ap_hsm=p.ap, ar_box=r.ar, tp_sign_pk=p.tp.pubkey(), now=NOW)
    cmm = U.d3_open_cmm(user_hsm=p.user, cmm_box=A.ap_send_cmm(session=r.sess, cmm=CMM))
    r.paci = U.d3_build_paci(user_hsm=p.user, ap_enc_pk=p.ap.enc_pub(),
                             cmm_version=cmm["version"], selection=SELECTION,
                             request_id="paci-1")
    r.par, r.arec = A.ap_build(ap_hsm=p.ap, session=r.sess, paci_box=r.paci,
                               cmm_version=CMM["version"], resolve=resolve,
                               sup_pub=sup.public(), domain2="ap.example", now=NOW,
                               application_id=APP_ID, record_id=REC_ID)
    r.verified = U.d5_accept_par(user_hsm=p.user, par_box=r.par, cred=r.cred,
                                 application_id=APP_ID, **p.keys)
    r.didgr = U.d5_build_didgr(user_hsm=p.user, verified=r.verified,
                               tp_enc_pk=p.tp.enc_pub(), request_id="didgr-1", expires=EXP)
    r.final, r.trec2 = T.tp_finalize(tp_hsm=p.tp, didgr_box=r.didgr, rec=r.trec,
                                     sup_pub=sup.public(), domain1="tp.example", now=NOW,
                                     application_id=APP_ID,
                                     **{"tp_sign_pk": p.tp.pubkey(), "ap_sign_pk": p.ap.pubkey()})
    r.did, r.phc2 = U.d6_accept_final(user_hsm=p.user, final_box=r.final,
                                      verified=r.verified, **p.keys)
    return r


_SHARED: list = []


def shared() -> Run:
    """同一进程里只跑一遍完整链路（约 15 秒），单元与对抗测试共用。只读，别改它。"""
    if not _SHARED:
        _SHARED.append(full())
    return _SHARED[0]


__all__ = ["Parties", "Run", "g1", "through_g4", "full", "shared", "resolve", "v1", "U", "T", "A",
           "NOW", "EXP", "PII", "BI", "CMM", "SELECTION", "sup_key"]
