"""crypto.sdk.v1 —— tpaa_v1 的受限对外入口。

业务侧写法（guard R2）：`import crypto.sdk` 后用 `crypto.sdk.v1.issue_phc(...)`。
"""

from __future__ import annotations

from collections.abc import MutableMapping

from ..primitives.group import G as EC_G, N as EC_Q, P as EC_P, ser_point
from ..hsm.v1 import SlotError, V1SoftHSM
from ..tpaa_v1.engine import (
    AfState, Issued, algorithm1, algorithm2, commit_af, hcgen, issue_phc,
    rebind_af, verify_holder, verify_public,
)
from ..tpaa_v1.params import G as DL_G, P as DL_P, Q as DL_Q, PARAMS_ID, in_subgroup, rand_exp
from ..tpaa_v1.schema import JSONLD_CONTEXT, PROFILE, PHCv1, af_ref, from_jsonld, to_jsonld
from ..tpaa_v1.supervision import (
    compute_irf, compute_rf, compute_s_ap, ecid_mask, open_ecid, reveal_hid, seal_ecid,
)


from ..tpaa_v1 import proto_ap as ap, proto_tp as tp, proto_user as user  # noqa: E402
from ..tpaa_v1 import auth, case, identity_evidence, initialization, records  # noqa: E402
from ..tpaa_v1.pke import PkeError  # noqa: E402
from ..tpaa_v1.wire import ProtocolError, hid_of, owner_of, pk_from_hex, pk_hex  # noqa: E402
# 运行时可信层（packages/tpaa_runtime/trust.py）用：域分离签名 / 验签 / 规范化摘要
from ..tpaa_v1.wire import check_sig, json_digest, phc_digest, sign  # noqa: E402


def make_demo_hsm(*, domain: str, root: bytes | None = None,
                  bindings: MutableMapping | None = None, **kw) -> V1SoftHSM:
    """⚠️ 演示 / 测试用。生产从 HSM/KMS 注入。

    domain：TP / AP（协议）、USER（钱包）、REVIEW（审批证据签名）、
            AUTH（令牌签发方）、STAFF（审核员 / 运营人员个人密钥）、
            IDV（独立身份核验方，仅测试适配器）。
    """
    if domain not in ("TP", "AP", "USER", "REVIEW", "AUTH", "STAFF", "IDV"):
        raise ValueError(f"未知的 HSM 域：{domain}")
    return V1SoftHSM(domain=domain, root=root, bindings=bindings, **kw)


def new_hsm_seed() -> dict:
    """生成一份 HSM 种子（十六进制）。⚠️ 演练形态：种子即私钥，落盘就是明文私钥。"""
    import secrets

    from ..primitives.group import N

    return {"schnorr_sk": format(secrets.randbelow(N - 1) + 1, "x"),
            "chameleon_sk": format(secrets.randbelow(N - 1) + 1, "x"),
            "root": secrets.token_bytes(32).hex()}


def hsm_from_seed(*, domain: str, seed: dict,
                  bindings: MutableMapping | None = None) -> V1SoftHSM:
    try:
        return make_demo_hsm(domain=domain, root=bytes.fromhex(seed["root"]),
                             schnorr_sk=int(seed["schnorr_sk"], 16),
                             chameleon_sk=int(seed["chameleon_sk"], 16),
                             bindings=bindings)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{domain} 的 HSM 种子缺少或损坏 schnorr_sk / chameleon_sk / root") from exc


__all__ = [
    "PROFILE", "JSONLD_CONTEXT", "PARAMS_ID", "PHCv1", "AfState", "Issued", "SlotError", "V1SoftHSM",
    "EC_G", "EC_Q", "EC_P", "DL_G", "DL_Q", "DL_P", "ser_point", "in_subgroup",
    "make_demo_hsm", "rand_exp", "commit_af", "rebind_af", "issue_phc",
    "algorithm1", "algorithm2", "verify_public", "verify_holder", "hcgen",
    "af_ref", "to_jsonld", "from_jsonld",
    "compute_irf", "compute_s_ap", "compute_rf", "reveal_hid",
    "seal_ecid", "ecid_mask", "open_ecid",
    "user", "tp", "ap", "auth", "case", "identity_evidence", "initialization", "records", "ProtocolError", "PkeError", "hid_of", "owner_of",
    "pk_hex", "pk_from_hex", "new_hsm_seed", "hsm_from_seed",
    "sign", "check_sig", "json_digest", "phc_digest",
]
