"""tpaa_v1 引擎：G1 / G3 / 算法1 / 算法2 / 校验 / HCGen。

谁做什么（每个函数只收它那一方该有的句柄）：
    commit_af        User   式 3：AF = h(ID)·A·T·g^r（初始两指数为 1）
    rebind_af        TP/AP  CCH：在自己的槽位上把指数换掉，AF 不变，返回新 r
    issue_phc        TP     G3：TPM / TPproof / TPCH / APCH / CHproof
    algorithm1       AP     APM / APproof / APCH 碰撞（AF 的重绑另由 rebind_af 做）
    algorithm2       TP     TPM.CDID 写入 / TPproof / TPCH 碰撞
    verify_public    任何人 只用公钥：三个签名 + AFRef
    verify_holder    TP/AP  再加上自己手里的 r：TPCH / APCH 能否重算

随机数的去向（errata E3）：r_tp 只回给 TP 自己，r_ap 只回给 AP，都不进 PHC。
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..primitives.chameleon import PublicChameleon
from ..primitives.group import ser_point
from ..primitives.schnorr import SchnorrSig, verify as schnorr_verify
from . import cch
from .encoding import digest
from .params import Q
from .schema import APM, TPM, PHCv1, af_ref


def _require(hsm, domain: str, who: str) -> None:
    if getattr(hsm, "domain", None) != domain:
        raise PermissionError(f"{who} 只能由 {domain} 的 HSM 执行（收到 {getattr(hsm, 'domain', None)!r}）")


# ---------------------------------------------------------------------------
# AF（CCH）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AfState:
    """一张凭证的 AF 状态。持有方：用户、TP、AP 各存一份（都不进 PHC）。"""
    af: int
    a_pub: int
    t_pub: int
    x_a: int
    x_t: int
    r: int

    def holds(self, hid: int) -> bool:
        return cch.af_holds(self.af, hid=hid, a_pub=self.a_pub, t_pub=self.t_pub,
                            x_a=self.x_a, x_t=self.x_t, r=self.r)


def commit_af(*, hid: int, a_pub: int, t_pub: int, r: int) -> AfState:
    """G1（用户）：式 3。"""
    x0 = cch.INITIAL_EXPONENT
    af = cch.af_value(hid=hid, a_pub=a_pub, t_pub=t_pub, x_a=x0, x_t=x0, r=r)
    return AfState(af=af, a_pub=a_pub, t_pub=t_pub, x_a=x0, x_t=x0, r=r % Q)


def rebind_af(state: AfState, *, hsm, hid: int, nonce: str, owner: str,
              kind: str, value) -> AfState:
    """CCH：TP 把 x_t 换成 X(IRF)（G2），或 AP 把 x_a 换成 X(CMI)（算法1 / U3）。

    ★ 先核验旧等式再求碰撞：等式不成立时 HSM 不会被调用 ——
      否则任何人拿一组伪造的 (AF, r) 就能让 HSM 吐出一个 r'。
    """
    if not state.holds(hid):
        raise ValueError("AF 等式不成立 —— 拒绝在不一致的状态上求碰撞")
    x_new = cch.exponent_of(kind, value)
    if kind == "IRF":
        _require(hsm, "TP", "rebind_af(IRF)")
        mine, x_old = state.t_pub, state.x_t
    else:
        _require(hsm, "AP", "rebind_af(CMI)")
        mine, x_old = state.a_pub, state.x_a
    if hsm.slot_public(nonce) != mine:
        raise PermissionError("槽位与这张凭证的陷门公钥不符")
    r_new = hsm.cch_collide(nonce=nonce, owner=owner, af=state.af,
                            x_old=x_old, x_new=x_new, r=state.r)
    out = replace(state, r=r_new, **({"x_t": x_new} if kind == "IRF" else {"x_a": x_new}))
    if not out.holds(hid):
        raise RuntimeError("碰撞后 AF 等式不成立 —— HSM 行为异常")
    return out


# ---------------------------------------------------------------------------
# G3 / 算法1 / 算法2
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Issued:
    phc: PHCv1
    r_tp: int          # → TP 本地库
    r_ap: int          # → EN_pk_ap(r_ap) 经 TPAC 交给 AP


def issue_phc(*, tp_hsm, ap_ch: PublicChameleon, ap_pk, af: int,
              ecid: str, time: str) -> Issued:
    _require(tp_hsm, "TP", "issue_phc")
    if callable(getattr(ap_ch, "has_trapdoor", None)) and ap_ch.has_trapdoor():
        raise PermissionError("红线 1：issue_phc 只收 AP 的公钥句柄")
    phc = PHCv1(tpm=TPM(time=time, cdid="", af=af, ecid=ecid),
                apm=APM(), tpid=ser_point(tp_hsm.pubkey()), apid=ser_point(ap_pk))
    phc.tpproof = tp_hsm.sign(phc.tpproof_msg()).to_bytes()

    tp_pub = tp_hsm.public_chameleon()
    r_tp, r_ap = tp_pub.rand(), ap_ch.rand()
    phc.tpch = tp_pub.compute(phc.tpch_msg(), r_tp)
    phc.apch = ap_ch.compute(phc.apch_msg(), r_ap)
    phc.chproof = tp_hsm.sign(phc.chproof_msg()).to_bytes()
    return Issued(phc=phc, r_tp=r_tp, r_ap=r_ap)


def algorithm1(phc: PHCv1, *, ap_hsm, r_ap: int, cmi: str, time: str) -> tuple[PHCv1, int]:
    """AP 写 APM，APCH 取值不变。返回 (PHC', r_ap')。"""
    _require(ap_hsm, "AP", "algorithm1")
    if ap_hsm.chameleon_compute(phc.apch_msg(), r_ap) != phc.apch:
        raise ValueError("r_ap 打不开这张凭证的 APCH —— 不是这张凭证的修改因子")
    old_m = phc.apch_msg()
    out = replace(phc, apm=APM(time=time, cmi=cmi, af_ref=af_ref(phc.tpm.af)),
                  version=phc.version + 1)
    out.approof = ap_hsm.sign(out.approof_msg()).to_bytes()
    _, r_new = ap_hsm.chameleon_collide((old_m, r_ap), out.apch_msg())
    if ap_hsm.chameleon_compute(out.apch_msg(), r_new) != out.apch:
        raise RuntimeError("APCH 碰撞失败")
    return out, r_new


def algorithm2(phc: PHCv1, *, tp_hsm, r_tp: int, cdid: str, time: str,
               ecid: str | None = None) -> tuple[PHCv1, int]:
    """TP 写 CDID（D6），TPCH 取值不变。返回 (PHC'', r_tp')。"""
    _require(tp_hsm, "TP", "algorithm2")
    if tp_hsm.chameleon_compute(phc.tpch_msg(), r_tp) != phc.tpch:
        raise ValueError("r_tp 打不开这张凭证的 TPCH")
    old_m = phc.tpch_msg()
    tpm = replace(phc.tpm, time=time, cdid=cdid, ecid=phc.tpm.ecid if ecid is None else ecid)
    out = replace(phc, tpm=tpm, version=phc.version + 1)
    out.tpproof = tp_hsm.sign(out.tpproof_msg()).to_bytes()
    _, r_new = tp_hsm.chameleon_collide((old_m, r_tp), out.tpch_msg())
    if tp_hsm.chameleon_compute(out.tpch_msg(), r_new) != out.tpch:
        raise RuntimeError("TPCH 碰撞失败")
    return out, r_new


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------


def _sig_ok(pk, msg: bytes, raw: bytes) -> bool:
    try:
        return schnorr_verify(pk, msg, SchnorrSig.from_bytes(raw))
    except (ValueError, TypeError):
        return False


def verify_public(phc: PHCv1, *, tp_pk, ap_pk) -> list[str]:
    """只用公钥能验的部分。返回错误列表，空表示通过。"""
    errs: list[str] = []
    if phc.tpid != ser_point(tp_pk):
        errs.append("TPid 与受信 TP 公钥不符")
    if phc.apid != ser_point(ap_pk):
        errs.append("APid 与受信 AP 公钥不符")
    if not _sig_ok(tp_pk, phc.tpproof_msg(), phc.tpproof):
        errs.append("TPproof 无效")
    if not _sig_ok(tp_pk, phc.chproof_msg(), phc.chproof):
        errs.append("CHproof 无效")
    if phc.apm.cmi or phc.approof:
        if not _sig_ok(ap_pk, phc.approof_msg(), phc.approof):
            errs.append("APproof 无效")
        if phc.apm.af_ref != af_ref(phc.tpm.af):
            errs.append("APM.AFRef 与本凭证的 AF 不符（APM 可能来自另一张凭证）")
    return errs


def verify_holder(phc: PHCv1, *, tp_pk, ap_pk, tp_ch: PublicChameleon,
                  ap_ch: PublicChameleon, r_tp: int | None = None,
                  r_ap: int | None = None) -> list[str]:
    """持有 r 的一方（TP / AP）额外能验：内容确实落在 CHproof 签过的哈希上。"""
    errs = verify_public(phc, tp_pk=tp_pk, ap_pk=ap_pk)
    if r_tp is not None and tp_ch.compute(phc.tpch_msg(), r_tp) != phc.tpch:
        errs.append("TPCH 与内容不符")
    if r_ap is not None and ap_ch.compute(phc.apch_msg(), r_ap) != phc.apch:
        errs.append("APCH 与内容不符")
    return errs


# ---------------------------------------------------------------------------
# HCGen（式 8，errata E9）
# ---------------------------------------------------------------------------


def hcgen(modules: list[tuple[str, str, str]], hid: int) -> str:
    """CMI = HCGen((CMC_i), H(ID))。

    链起点 c_0 = H("HCGen/seed", H(ID))，每一层 c_i = H("HCGen/link", c_{i-1}, id, ver, digest)。
    顺序即功能分类顺序 i = 1..N，由调用方给定、不在这里重排 ——
    重排会让"同一组模块换个分类位置"得到同一个 CMI。
    """
    if not modules:
        raise ValueError("HCGen 至少需要一个模块")
    c = digest("HCGen/seed", hid)
    for mid, ver, dig in modules:
        c = digest("HCGen/link", c, mid, ver, dig)
    return c.hex()


__all__ = ["AfState", "commit_af", "rebind_af", "Issued", "issue_phc",
           "algorithm1", "algorithm2", "verify_public", "verify_holder", "hcgen"]
