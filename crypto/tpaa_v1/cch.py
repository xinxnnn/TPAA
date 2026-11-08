"""CCH —— 锚定因子 AF 的定制变色龙哈希（说明书 G2 / 算法1，errata E1）。

    AF = h(ID) · A^{x_a} · T^{x_t} · g^{r}   (mod p)

    h(ID) = g^{H(ID) mod q}           身份锚，不可变
    A = g^a                           AP 为这张凭证分配的陷门公钥（原文 pk_ap）
    T = g^t                           TP 为这张凭证分配的陷门公钥（原文 pk_tp）
    x_t = X("IRF", IRF)               G2 由 TP 写入（原文指数 IRF/CRF）
    x_a = X("CMI", CMI)               算法1 由 AP 写入（原文指数 CMI）
    初始两个指数都是 1（式 3）

碰撞：持有 a 的一方把 x_a 从 x_old 改到 x_new，AF 取值不变：
    a·x_old + r = a·x_new + r'   ⇒   r' = r + a·(x_old − x_new)  (mod q)

★ errata E1（为什么不用原文的 pk_ap / pk_tp）：
  原文的陷门就是 sk_tp / sk_ap 本身。用户同时知道 r_bind 与 r_bind'，
  由上式即可解出 sk_tp = (r' − r)/(1 − x)。sk_tp 又是签名与解密私钥 ——
  任何一个用户都能拿到 TP 的主私钥。
  这里改为**每张凭证一对陷门**（A, T），由各自 HSM 按槽位派生：
  用户最多解出自己这张凭证的 a / t，碰不到主私钥，也碰不到别人的凭证。

★ 指数 X(·) 是哈希到 Z_q：IRF 是 Paillier 密文（mod n²，远大于 q），
  CMI 是十六进制串。原文没说怎么把它们放进指数，这里用带域分离的哈希固定下来。
"""

from __future__ import annotations

from .encoding import h_int
from .params import G, P, Q, in_subgroup

INITIAL_EXPONENT = 1


def hid_elem(hid: int) -> int:
    """h(ID)：把身份哈希映射进 q 阶子群。"""
    return pow(G, h_int("cch/hid", hid, mod=Q), P)


def exponent_of(kind: str, value) -> int:
    if kind not in ("IRF", "CMI"):
        raise ValueError(f"未知的 AF 指数类别：{kind}")
    return h_int("cch/x", kind, value, mod=Q)


def af_value(*, hid: int, a_pub: int, t_pub: int, x_a: int, x_t: int, r: int) -> int:
    for name, v in (("A", a_pub), ("T", t_pub)):
        if not in_subgroup(v):
            raise ValueError(f"陷门公钥 {name} 不在 q 阶子群内")
    return (hid_elem(hid) * pow(a_pub, x_a, P) * pow(t_pub, x_t, P)
            * pow(G, r % Q, P)) % P


def af_holds(af: int, **kw) -> bool:
    try:
        return af_value(**kw) == af
    except ValueError:
        return False


def collide_r(trapdoor: int, x_old: int, x_new: int, r: int) -> int:
    """求碰撞随机数。★ 陷门进入的唯一函数：guard R4 只放行本文件与 crypto/hsm/v1.py。"""
    return (r + trapdoor * (x_old - x_new)) % Q


__all__ = ["INITIAL_EXPONENT", "hid_elem", "exponent_of", "af_value", "af_holds", "collide_r"]
