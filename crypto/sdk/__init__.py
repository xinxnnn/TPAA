"""crypto/sdk —— 上层调用密码学能力的**唯一受限入口**（ARCHITECTURE §crypto/sdk）。

红线 2 的可强制实现：crypto.guard 仅放行 `crypto.sdk` / `crypto.hsm` 两个入口，
任何业务代码直连 crypto.primitives / crypto.phc / crypto.derivation /
crypto.envelope 都会在 CI 失败。

本包重新导出各密码引擎的对外函数，并把 HSM 句柄一并暴露，使上层不必（也不应）
接触任何内部密钥材料。生产环境把 `SoftHSM` 换成真实 HSM/KMS 适配即可。
"""

from __future__ import annotations

from .phc import issue_phc, update_by_ap, update_by_tp, verify_phc
from .paillier import (
    SupervisionKey,
    SupervisionPublic,
    make_supervision_key,
    supervision_public_from_n,
    seal_identity,
    open_identity,
)
from .derivation import (
    derive_child_phc,
    seal_child_did,
    verify_lineage,
    trace_to_root,
    cascade_revoke,
    DerivationRecord,
)
from .envelope import seal_secinfo, unseal_secinfo, protect_cid, recover_cid
from .phc_io import phc_obj_to_json, phc_json_to_obj, phc_verify, phc_ap_pubkey
from .keys import (
    hash_chain,
    hash_chain_layers,
    first_divergence,
    as_public,
    ser_point,
    point_from_bytes,
    public_from_cpk,
    public_from_hex,
)
from ..hsm import SoftHSM, HSM
from . import v1  # tpaa_v1 profile：业务侧用 crypto.sdk.v1.xxx


__all__ = [
    "SoftHSM", "HSM",
    "issue_phc", "update_by_ap", "update_by_tp", "verify_phc",
    "derive_child_phc", "seal_child_did", "verify_lineage",
    "trace_to_root", "cascade_revoke", "DerivationRecord",
    "seal_secinfo", "unseal_secinfo", "protect_cid", "recover_cid",
    "phc_obj_to_json", "phc_json_to_obj", "phc_verify", "phc_ap_pubkey",
    "hash_chain", "hash_chain_layers", "first_divergence",
    "as_public", "ser_point", "point_from_bytes", "public_from_cpk", "public_from_hex",
    "make_demo_hsm", "v1",
    "SupervisionKey", "SupervisionPublic",
    "make_supervision_key", "supervision_public_from_n",
    "seal_identity", "open_identity",
]


def make_demo_hsm(*, domain: str, schnorr_sk=None, chameleon_sk=None) -> SoftHSM:
    """演示用 HSM 工厂（测试 / 本地演练）。

    ⚠️ 生产环境不得使用本函数：真实部署应注入真实 HSM/KMS 句柄，
       私钥 / 陷门永不离开硬件边界。

    要用句柄做跨域协同，调 `hsm.public_chameleon()` —— 它只给出公钥，
    算得出值但改写不了内容。步骤 9 之前这里有个 `demo_chameleon()`，
    会把**含陷门**的内部对象原样交出去，等于把 AP 的改写权送给协程方，
    已移除；跨域只认 public_chameleon 一种出口。
    """
    return SoftHSM(domain=domain, schnorr_sk=schnorr_sk, chameleon_sk=chameleon_sk)
