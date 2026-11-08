"""PHC 签发与更新引擎。

三个动作：

    issue_phc()     G3  —— TP 初始化并签发 PHC（APM 此时为空）
    update_by_ap()  算法1 —— AP 写入 CMI 与时间戳，APCH 取值不变
    update_by_tp()  算法2 —— TP 写入 DID 并重新封印

★ 算法1 是整套方案的核心：AP 改了内容，但 TP 的签名继续有效，
  且 TP 全程不需要参与。这不是绕过签名，而是变色龙哈希的性质。

★ HSM 注入式（步骤 9）
  本模块**不再接受任何原始密钥标量**（tp_sk / ap_sk 之类）。
  要用谁的私钥，就注入谁的 HSM 句柄，签名与碰撞都在句柄内部完成，
  私钥与陷门全程不进本模块的调用栈。

  跨域协同的那半——TP 签发时要为 AP 预留 APCH 的位置——只传
  `PublicChameleon`：算得出值，改写不了内容。若把含陷门的对象塞进来，
  等于把 AP 的改写权白送给 TP，算法1 的"AP 独自完成"就名存实亡。
"""

from __future__ import annotations

from ..hsm.base import HSM
from ..primitives import (
    PublicChameleon,
    SchnorrSig,
    as_public,
    require_public,
    ser_point,
    verify,
)
from .schema import PHC, _h


def reject_raw_keys(rejected: dict) -> None:
    """收口守卫：既给出明确的安全提示，也不吞掉普通的拼写错误。

    phc 与 derivation 两个引擎共用 —— 一处定义，两处生效。
    """
    if not rejected:
        return
    raw = sorted(k for k in rejected if k.endswith("_sk"))
    if raw:
        raise TypeError(
            f"红线 1：{', '.join(raw)} 是原始密钥标量，PHC 引擎已改为 HSM 注入式，不再接受。"
            "请改为注入句柄 tp_hsm= / ap_hsm=（handle，而非 key）。"
        )
    raise TypeError(f"未预期的参数：{sorted(rejected)}")


def _require_domain(hsm: HSM, expected: str, action: str) -> None:
    """双域隔离：拿错句柄当场失败，而不是签完才发现签名人不对。"""
    got = getattr(hsm, "domain", None)
    if got is not None and got != expected:
        raise PermissionError(
            f"{action} 是 {expected} 侧动作，却拿到了 {got} 的 HSM 句柄。"
            "双域隔离要求两方各自持有独立密钥。"
        )


# ---------------------------------------------------------------------------
# G3：TP 初始化并签发
# ---------------------------------------------------------------------------


def issue_phc(
    *,
    tp_hsm: HSM,
    ap_ch: PublicChameleon,
    identity_hash: int,
    tau: int,
    crf: int,
    tpm_time: str,
    tpm_ecid: str,
    apid: bytes = b"",
    parent_did: str = "",
    **rejected,
) -> PHC:
    """TP 签发初始 PHC。ASO.APM 此刻为空，等 AP 后续用算法1 填充。

    注意传入的是 **AP 的公钥句柄**：TP 只需要能算出 APCH，不需要能改写它。

    ★ `parent_did` 必须在**签发时**给出，不能事后补：
      AF = CH_TP(H(ID) ‖ τ ‖ CRF ‖ APCH ‖ parent_did)，它在第 2 步就被算定。
      事后把 parent_did 塞进 PHC，AF 里的那一项仍是空串 —— 两份内容从此永久错位，
      而它不在任何可改写的范围内（AF 只能由 TP 用陷门重算）。
      所以子体的 parent_did 一定得在这条路径上进来，而不是在 update_by_tp 里补。
    """
    reject_raw_keys(rejected)
    _require_domain(tp_hsm, "TP", "issue_phc")
    ap_ch = require_public(ap_ch, "issue_phc(ap_ch)")

    phc = PHC(version=1, tpm_time=tpm_time, tpm_ecid=tpm_ecid)
    phc.apa_apid = apid          # ★ 必须在算 APCH 之前设好，否则消息不一致
    phc.parent_did = parent_did  # ★ 必须在算 AF 之前设好（理由见 docstring）

    tp_pub = tp_hsm.public_chameleon()

    # 1) 先算 APCH（APM 为空）—— 用 AP 的变色龙公钥，只有 AP 能后续改写
    phc.proof_apch_r = ap_ch.rand()
    phc.proof_apch = ap_ch.compute(phc.apch_message(), phc.proof_apch_r)

    # 2) 再算 AF —— 把身份哈希、绑定因子、监管因子与 APCH 一起锚定
    m_af = phc.af_message(identity_hash, tau, crf)
    r_af = tp_pub.rand()
    phc.tpm_af = tp_pub.compute(m_af, r_af)
    phc.tpm_af_r = r_af

    # 3) TP 背书：对 TPM 与自己的身份签名（签名动作在 HSM 内完成）
    phc.tpa_tpid = ser_point(tp_hsm.pubkey())
    phc.tpa_proof = tp_hsm.sign(_h(phc.tpm_message(), phc.tpa_tpid).to_bytes(32, "big")).to_bytes()

    # 4) TPCH 覆盖 TPM 与 TPA
    phc.proof_tpch_r = tp_pub.rand()
    phc.proof_tpch = tp_pub.compute(phc.tpch_message(), phc.proof_tpch_r)

    # 5) 整体签名：Sign_TP( TPCH ‖ APCH )
    phc.proof_chproof = tp_hsm.sign(phc.signed_digest()).to_bytes()

    return phc


# ---------------------------------------------------------------------------
# 算法1：AP 驱动更新
# ---------------------------------------------------------------------------


def update_by_ap(
    phc: PHC,
    *,
    ap_hsm: HSM,
    cmi: str,
    apm_time: str,
    apid: bytes | None = None,
    **rejected,
) -> PHC:
    """AP 写入模块承诺 CMI 与时间戳。

    AP 持有 APCH 的陷门，可以求出碰撞使 **APCH 取值不变**，
    从而 AF 不必改、TP 的 CHproof 继续有效。

    碰撞这一步是整个方案里唯一需要陷门的动作，它走 `ap_hsm.chameleon_collide`，
    陷门不进本函数的作用域。
    """
    reject_raw_keys(rejected)
    _require_domain(ap_hsm, "AP", "update_by_ap")

    old_apch_m = phc.apch_message()          # 改动前

    phc.apm_time = apm_time
    phc.apm_cmi = cmi
    if apid is not None:
        phc.apa_apid = apid
    phc.apa_proof = ap_hsm.sign(_h(phc.apm_message(), phc.apa_apid).to_bytes(32, "big")).to_bytes()

    new_apch_m = phc.apch_message()          # 改动后
    _, phc.proof_apch_r = ap_hsm.chameleon_collide((old_apch_m, phc.proof_apch_r), new_apch_m)

    phc.version += 1
    return phc


# ---------------------------------------------------------------------------
# 算法2：TP 驱动更新（生成 DID）
# ---------------------------------------------------------------------------


def update_by_tp(
    phc: PHC,
    *,
    tp_hsm: HSM,
    did: str,
    tpm_time: str | None = None,
    parent_did: str | None = None,
    **rejected,
) -> PHC:
    """TP 写入 DID 并重新封印。

    注意：TP 改的是**自己那半**字段（TPM），TPCH 取值会变，
    因此必须由 TP 重新签名。这与算法1 形成对照：
        AP 改 APM → APCH 值不变 → 不需 TP 参与
        TP 改 TPM → TPCH 值变   → 由 TP 自己重签
    """
    reject_raw_keys(rejected)
    _require_domain(tp_hsm, "TP", "update_by_tp")

    if tpm_time is not None:
        phc.tpm_time = tpm_time
    if parent_did is not None:
        phc.parent_did = parent_did
    phc.tpm_cdid = did

    tp_pub = tp_hsm.public_chameleon()

    phc.tpa_tpid = ser_point(tp_hsm.pubkey())
    phc.tpa_proof = tp_hsm.sign(_h(phc.tpm_message(), phc.tpa_tpid).to_bytes(32, "big")).to_bytes()

    phc.proof_tpch_r = tp_pub.rand()
    phc.proof_tpch = tp_pub.compute(phc.tpch_message(), phc.proof_tpch_r)

    phc.proof_chproof = tp_hsm.sign(phc.signed_digest()).to_bytes()
    phc.version += 1
    return phc


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------


def verify_phc(
    phc: PHC,
    *,
    tp_pk,
    ap_pk,
    tp_ch: PublicChameleon,
    ap_ch: PublicChameleon,
    identity_hash: int,
    tau: int,
    crf: int,
) -> list[str]:
    """完整校验。返回错误列表；空列表表示通过。

    校验是公开动作 —— 只用公钥，因此传 `PublicChameleon` 就够，
    持有完整 ChameleonHash 也能校验（它是子类），但没必要：
    进来先降级，这个作用域里就不存在陷门可被顺手用掉。
    """
    tp_ch = as_public(tp_ch)
    ap_ch = as_public(ap_ch)

    errs: list[str] = []

    # 1. APCH 完整性
    if ap_ch.compute(phc.apch_message(), phc.proof_apch_r) != phc.proof_apch:
        errs.append("APCH 与 APM/APA 内容不一致")

    # 2. TPCH 完整性
    if tp_ch.compute(phc.tpch_message(), phc.proof_tpch_r) != phc.proof_tpch:
        errs.append("TPCH 与 TPM/TPA 内容不一致")

    # 3. AF 锚定
    if tp_ch.compute(phc.af_message(identity_hash, tau, crf), phc.tpm_af_r) != phc.tpm_af:
        errs.append("AF 锚定不一致（身份因子或监管因子被动过）")

    # 4. TP 对整体承诺的签名
    if not verify(tp_pk, phc.signed_digest(), SchnorrSig.from_bytes(phc.proof_chproof)):
        errs.append("TP 对 (TPCH‖APCH) 的签名无效")

    # 5. TP 背书
    if phc.tpa_proof:
        if not verify(tp_pk, _h(phc.tpm_message(), phc.tpa_tpid).to_bytes(32, "big"),
                      SchnorrSig.from_bytes(phc.tpa_proof)):
            errs.append("TP 背书 TPA.proof 无效")

    # 6. AP 背书
    if phc.apa_proof:
        if not verify(ap_pk, _h(phc.apm_message(), phc.apa_apid).to_bytes(32, "big"),
                      SchnorrSig.from_bytes(phc.apa_proof)):
            errs.append("AP 背书 APA.proof 无效")

    return errs
