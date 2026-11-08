"""监管因子与加密内容标识（式 5 / 6 / 9，R1 / R2；errata E4 / E5 / E6）。

    IRF  = PEnc_ppk(H(ID))                     式 5（TP，G2）
    s_ap = PRF(sk_ap, AF)                      D4（AP）
    RF   = IRF · PEnc_ppk(s_ap)  (mod n²)      式 9 —— 同态加法，RF 封的是 H(ID) + s_ap
    R1   H(ID) = PDec_psk(RF) − s_ap  (mod n)  TP 解密，AP 交回 s_ap 后才能减掉

★ E4：R1 原文写 s_ap = PRF(sk_tp, AF)，与 D4 的 PRF(sk_ap, AF) 不一致。
  按 sk_ap 实现：用 sk_tp 算出的值减不掉 RF 里的那一项，而且 AP 根本没有 sk_tp。
★ E6：原文 PEnc_psk（"用私钥加密"）按 ppk 实现；解密结果 mod n（原文写成 mod n²）。
★ E5：式 6 的 ECID = PEnc(CID + sk_tp·RF) 依赖 RF，而 RF 要到 D4 才有。
  拆成两步：G2 先封 PEnc(CID)；D6 拿到 RF 后按式 6 重封（reseal_ecid）。
  式 6 里的 sk_tp 按 E2 换成 TP 的 PRF 派生量 k_tp = PRF(sk_tp, "ecid")。

⚠️ 限界：TP 自己存着 r_bind 与 H(ID) 的对照（原文 G3 的本地库），
  所以 TP 可以不经 AP 把 DID 关联到 H(ID)。本模块保证的是
  「AP 单独揭露不了」与「按 R1 走协议必须 AP 交回 s_ap」，
  **不保证** TP 单方无法关联身份（errata S2）。
"""

from __future__ import annotations

from ..hsm.supervision import SupervisionKey, SupervisionPublic

S_AP_BITS = 256


def compute_irf(hid: int, pub: SupervisionPublic) -> int:
    return pub.seal(hid)


def compute_s_ap(ap_hsm, af: int) -> int:
    """AP 侧：s_ap = PRF(sk_ap, AF)。只在 AP 的 HSM 里算。"""
    if getattr(ap_hsm, "domain", None) != "AP":
        raise PermissionError("s_ap 只能由 AP 的 HSM 计算")
    return ap_hsm.prf("s_ap", af)


def compute_rf(irf: int, s_ap: int, pub: SupervisionPublic) -> int:
    # Paillier 同态加法：Enc(a)·Enc(b) = Enc(a+b)。H(ID) 与 s_ap 都是 256 bit，和远小于 n
    return irf * pub.seal(s_ap) % (pub.n * pub.n)


def reveal_hid(rf: int, s_ap: int, key: SupervisionKey) -> int:
    """R1：TP 解密 RF，再减去 AP 交回的 s_ap。"""
    n = key.public().n
    return (key.open(rf) - s_ap) % n


# ---- ECID（式 6，两段式）----

_CID_MARK = b"\x01"   # 首字节非零：否则长度前缀的高位 0 会被整数编码吞掉


def _cid_int(cid: str) -> int:
    raw = cid.encode("utf-8")
    return int.from_bytes(_CID_MARK + len(raw).to_bytes(2, "big") + raw, "big")


def _cid_str(v: int) -> str:
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    ln = int.from_bytes(b[1:3], "big")
    if b[:1] != _CID_MARK or len(b) - 3 != ln:
        raise ValueError("ECID 解出的内容不是合法 CID —— 掩码项不对，或密文被换过")
    return b[3:].decode("utf-8")


def seal_ecid(cid: str, pub: SupervisionPublic, *, mask: int = 0) -> int:
    m = _cid_int(cid) + mask
    if m >= pub.n:
        raise ValueError("CID 过长，超出 Paillier 明文空间")
    return pub.seal(m)


def ecid_mask(tp_hsm, rf: int, n: int) -> int:
    """式 6 的 sk_tp·RF 项，按 E2 用 TP 的 PRF 密钥代替签名私钥。"""
    if getattr(tp_hsm, "domain", None) != "TP":
        raise PermissionError("ECID 掩码只能由 TP 的 HSM 计算")
    return tp_hsm.prf("ecid", rf) % (n // 4)


def open_ecid(ecid: int, key: SupervisionKey, *, mask: int = 0) -> str:
    n = key.public().n
    return _cid_str((key.open(ecid) - mask) % n)


__all__ = ["compute_irf", "compute_s_ap", "compute_rf", "reveal_hid",
           "seal_ecid", "ecid_mask", "open_ecid", "S_AP_BITS"]
