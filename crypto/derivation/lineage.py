"""子智能体的派生链。

按姐姐确认的模型：**子智能体走与主智能体完全相同的申领流程（D1-D6），
持有唯一 DID**。它与主智能体的关系不是"委托"，而是**密码学上封死的派生**：

    AFᵢ = CH_TP( H(ID) ‖ τᵢ ‖ CRFᵢ ‖ APCHᵢ ‖ DID₀ )
                                              ↑ 父 DID 构造时直接封进去

因为 AF 本身就是变色龙哈希，TP 在生成 AFᵢ 时把 DID₀ 放进消息即可，
不需要额外碰撞 —— 父子关系从构造那一刻起就不可否认。

由此得到两条能力：

    路径 A（直接执法）  子 DIDᵢ → RFᵢ → 解密 → H(ID) → 自然人
    路径 B（归属证明）  子 DIDᵢ → AFᵢ 解出 DID₀ → 主 PHC₀

以及一条必须实现的约束：

    主凭证吊销 → 按 parent_did 反查 → 全部子体即时失效（级联）

★ HSM 注入式（步骤 9）—— 由此得到本模块的实现纪律：

    这里**没有**任何函数需要原始密钥标量。
      derive_child_phc / verify_lineage 全是公开动作（只用 compute），
      进来什么句柄都先用 as_public 降级，陷门不进调用栈；
      唯一要签名动作的 seal_child_did 注入 TP 的 HSM 句柄，重签交给 update_by_tp。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..phc.engine import reject_raw_keys, update_by_tp
from ..phc.schema import PHC
from ..primitives import as_public


@dataclass
class DerivationRecord:
    """一次派生的存证。

    ★ 必须存证进审计链：子智能体可能任务结束即销毁，
      凭证若不留痕，追溯链在子体这一层就断了。
    """

    child_did: str
    parent_did: str
    agent_type: str = "sub"            # primary | sub
    purpose: str = ""
    ttl: str = ""                      # 临时子体的有效期
    confirmed_by_user: bool = False    # ★ 未确认的派生视为非法
    confirm_evidence: dict = field(default_factory=dict)
    derived_at: str = ""
    revoked: bool = False
    revoke_reason: str = ""


# ---------------------------------------------------------------------------
# 派生：给子体生成带父指针的 AF
# ---------------------------------------------------------------------------


def derive_child_phc(
    *,
    parent: PHC,
    parent_did: str,
    tp_ch,
    ap_ch,
    identity_hash: int,
    tau: int,
    crf: int,
    **rejected,
) -> PHC:
    """由主 PHC 派生出子体的 PHC 骨架（APM 留空，等算法1 填充）。

    这是**公开动作**：只需要算出 APCH 与 AF，不需要改写任何东西，
    因此两个句柄一到就被降级成公钥形态 —— 陷门不进本函数作用域。
    """
    reject_raw_keys(rejected)
    tp_pub = as_public(tp_ch)
    ap_pub = as_public(ap_ch)

    child = PHC(version=1)
    child.parent_did = parent_did

    # 继承主 PHC 的公开参数（这些不属于身份秘密）
    child.tpm_ecid = parent.tpm_ecid
    child.tpa_tpid = parent.tpa_tpid
    child.apa_apid = parent.apa_apid

    # APCH 必须由子体自己算（APM 为空）—— 不能复制父的，否则消息对不上
    child.proof_apch_r = ap_pub.rand()
    child.proof_apch = ap_pub.compute(child.apch_message(), child.proof_apch_r)

    # ★ 重新锚定 AF：把父 DID 封进去
    m_af = child.af_message(identity_hash, tau, crf)
    r_af = tp_pub.rand()
    child.tpm_af = tp_pub.compute(m_af, r_af)
    child.tpm_af_r = r_af

    return child


def seal_child_did(
    child: PHC,
    *,
    tp_hsm,
    did: str,
    tpm_time: str,
    **rejected,
) -> PHC:
    """TP 为子体写入唯一 DID 并封印（对应 D6 的派生变体）。

    这是本模块里唯一需要 TP 私钥的动作，因此注入 TP 的 HSM 句柄：
      1. 写 CDID 与时间戳（parent_did 早在 derive_child_phc 时已封进 AF 消息）
      2. 重算 TPCH
      3. 由 update_by_tp 在 HSM 内重新签名
    """
    reject_raw_keys(rejected)

    child.tpm_cdid = did
    child.tpm_time = tpm_time
    return update_by_tp(child, tp_hsm=tp_hsm, did=did, tpm_time=tpm_time)


# ---------------------------------------------------------------------------
# 校验与上溯
# ---------------------------------------------------------------------------


def verify_lineage(
    child: PHC,
    *,
    tp_ch,
    identity_hash: int,
    tau: int,
    crf: int,
    expected_parent_did: str,
    **rejected,
) -> list[str]:
    """校验子体的归属链：AF 里封的父 DID 是否与声称的一致。

    校验永远是公开动作 —— 只用公钥就够了，因此句柄先降级。
    """
    reject_raw_keys(rejected)
    tp_pub = as_public(tp_ch)

    errs: list[str] = []

    if child.parent_did != expected_parent_did:
        errs.append(f"声称的父 DID 与凭证字段不一致：{child.parent_did} != {expected_parent_did}")

    if tp_pub.compute(child.af_message(identity_hash, tau, crf), child.tpm_af_r) != child.tpm_af:
        errs.append("AF 锚定不一致 —— 父指针或身份因子被动过")

    return errs


def trace_to_root(
    did: str,
    records: dict[str, DerivationRecord],
    *,
    max_depth: int = 16,
) -> list[str]:
    """沿 parent_did 一路向上，返回 [子, ..., 主]。

    用于追溯时的**归属证明**：证明某个子体确实挂在哪个主 DID 下。
    """
    chain: list[str] = [did]
    cur = did
    for _ in range(max_depth):
        rec = records.get(cur)
        if rec is None or not rec.parent_did:
            break
        chain.append(rec.parent_did)
        cur = rec.parent_did
        if cur in chain[:-1]:        # 出现环，立即停
            break
    return chain


def cascade_revoke(
    root_did: str,
    records: dict[str, DerivationRecord],
    *,
    reason: str = "parent_revoked",
) -> list[str]:
    """主凭证吊销 → 把所有后代标记为失效。返回被级联的 DID 列表。

    ★ 只吊销主凭证而放任子体继续跑，等于吊销形同虚设。
    """
    affected: list[str] = []
    frontier = [root_did]
    seen = {root_did}

    while frontier:
        cur = frontier.pop()
        for did, rec in records.items():
            if rec.parent_did == cur and did not in seen:
                rec.revoked = True
                rec.revoke_reason = reason
                affected.append(did)
                seen.add(did)
                frontier.append(did)

    return affected
