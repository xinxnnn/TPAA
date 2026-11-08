"""说明书的 EN_pk(x) / DE_sk(x)（参数表："ElGamal 非对称加解密"）。

原文对任意长的消息（PHC、BI、PII、CMM…）做 ElGamal，没有给出编码方式。
这里实现成 ElGamal-KEM + encrypt-then-MAC（DHIES 结构），errata E15：

    seal：k ←$ Z_q;  c1 = g^k;  K = KDF("pke/" + tag, c1, pk^k)
          (nonce, ct, mac) = EtM(K, canonical_json(payload))
    open：K = KDF("pke/" + tag, c1, c1^x)，MAC 不对即拒

★ tag 是消息种类（CR / RR / AR / PAR / DIDGR / CSCID / CDID / FINAL）。
  它进 KDF，所以一个 RR 密文不能被当作 AR 交给对方解 —— 解出来的 MAC 一定不对。
★ c1 先查子群：不在 q 阶子群里的 c1 会把 pk^k 限制在小子群上（小子群攻击）。
"""

from __future__ import annotations

import json

from ..envelope.cipher import decrypt as etm_decrypt, encrypt as etm_encrypt
from ..envelope.kdf import derive_key
from .params import G, P, Q, in_subgroup, rand_exp


class PkeError(ValueError):
    """密文打不开：不是发给你的、类型不对，或者被改过。"""


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _key(tag: str, c1: int, shared: int) -> bytes:
    return derive_key(c1.to_bytes(384, "big"), shared.to_bytes(384, "big"),
                      salt=b"TPAA/v1/pke", info=("pke/" + tag).encode())


def seal(pk: int, payload: dict, *, tag: str) -> dict:
    if not in_subgroup(pk):
        raise PkeError("接收方加密公钥不在 q 阶子群内")
    k = rand_exp()
    c1 = pow(G, k, P)
    nonce, ct, mac = etm_encrypt(_key(tag, c1, pow(pk, k, P)), canonical_json(payload))
    return {"tag": tag, "c1": format(c1, "x"), "n": nonce.hex(), "ct": ct.hex(), "mac": mac.hex()}


def open_with(sk: int, box: dict, *, tag: str) -> dict:
    """只在 HSM 内调用（V1SoftHSM.pke_open）。"""
    if box.get("tag") != tag:
        raise PkeError(f"密文类型不符：期望 {tag}，收到 {box.get('tag')!r}")
    try:
        c1 = int(box["c1"], 16)
        nonce, ct, mac = (bytes.fromhex(box[k]) for k in ("n", "ct", "mac"))
    except (KeyError, ValueError) as e:
        raise PkeError("密文结构损坏") from e
    if not in_subgroup(c1):
        raise PkeError("c1 不在 q 阶子群内")
    pt = etm_decrypt(_key(tag, c1, pow(c1, sk % Q, P)), nonce, ct, mac)
    if pt is None:
        raise PkeError("解密失败：不是发给本方的密文，或已被篡改")
    return json.loads(pt)


__all__ = ["seal", "open_with", "canonical_json", "PkeError"]
