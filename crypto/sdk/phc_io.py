"""PHC 的**跨域交换形态**入口：JSON-LD 的读写与校验。

为什么这一步要放进 sdk，而不是让业务代码自己拼 dict：
    PHC 有 16 个字段，其中 8 个是十六进制整数、4 个是字节串。
    任何一个字段拼错，结果都是"验签失败"——而验签失败的现场几乎无法区分
    "传错了"和"被篡改了"。把编解码收在一处，业务侧就不可能拼错。

本模块三条约定：
    phc_obj_to_json / phc_json_to_obj   纯编解码，**不做校验**
    phc_verify                          只做校验，**不做修复**
    phc_ap_pubkey                       取 PHC 自带的 AP 公钥（已被签名保护）

为什么不在这里 export 能改写 PHC 的入口（update_by_ap 等）：
    那是"AP 拿自己的陷门改自己那半"的动作，属于持有 HSM 的一方才该做的事。
    业务层手里没有 HSM 的话拿到了也用不了；有 HSM 的话应该显式走
    `crypto.sdk.update_by_ap`（它要求传入 hsm 句柄），而不是从这里拐进来。
"""

from __future__ import annotations

from ..phc.schema import PHC

__all__ = ["phc_obj_to_json", "phc_json_to_obj", "phc_verify", "phc_ap_pubkey"]


def phc_obj_to_json(phc) -> dict:
    """PHC 对象 → JSON-LD dict（跨域只传这个形态）。"""
    if not isinstance(phc, PHC):
        raise TypeError(f"期望 PHC 对象，实际 {type(phc).__name__}")
    return phc.to_jsonld()


def phc_json_to_obj(doc: dict) -> PHC:
    """JSON-LD dict → PHC 对象。畸形字段会抛，由调用方转成"校验失败"。"""
    if not isinstance(doc, dict):
        raise TypeError(f"期望 dict，实际 {type(doc).__name__}")
    return PHC.from_jsonld(doc)


def phc_ap_pubkey(doc: dict):
    """取 PHC 里自带的 AP 公钥（33 字节压缩点）。

    这个值是**被签名保护过的公开输入**：它参与 APCH，APCH 参与 AF，
    AF 被 TPCH 锚定，TPCH 被 TP 签名覆盖。改它必然导致验签失败，
    所以拿去当验签的公钥是安全的，不是"信任调用方"。
    """
    return PHC.from_jsonld(doc).apa_apid


def phc_verify(doc: dict, *, tp_pk, ap_pk, tp_ch, ap_ch,
               identity_hash: int, tau: int, crf: int):
    """校验一份 JSON 形态的 PHC，返回 `PhcVerifyResult`-兼容的结果。

    返回类型刻意用 ports 里那个（ok + errors）的形状：
    sdk 不 import backend，所以这里返回一个同构的轻量对象即可，
    调用方按属性读，不关心具体类。
    """
    from ..phc.engine import verify_phc as _verify  # 延迟导入：引擎依赖 hsm，本模块只要编解码时不必拉起

    errs = _verify(
        PHC.from_jsonld(doc),
        tp_pk=tp_pk, ap_pk=ap_pk, tp_ch=tp_ch, ap_ch=ap_ch,
        identity_hash=identity_hash, tau=tau, crf=crf,
    )
    return VerifyOutcome(ok=not errs, errors=list(errs))


class VerifyOutcome:
    """与 ports.PhcVerifyResult 同构的最小结果对象（避免 sdk 反向依赖 backend）。"""

    __slots__ = ("ok", "errors")

    def __init__(self, *, ok: bool, errors: list[str]) -> None:
        self.ok = ok
        self.errors = errors

    def __repr__(self) -> str:                          # pragma: no cover - 调试用
        return f"VerifyOutcome(ok={self.ok}, errors={self.errors!r})"
