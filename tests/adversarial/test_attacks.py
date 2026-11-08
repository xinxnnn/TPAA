"""对抗性测试 —— 每一条都是"攻击必须失败"的断言。

    python run_tests.py

这些用例对应《完整系统方案》第 15.1 节的对抗清单。目前覆盖原语层；
后续接入 phc / derivation / supervision 后会继续扩充。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crypto.primitives import (  # noqa: E402
    ChameleonHash,
    ChameleonKey,
    G,
    N,
    Paillier,
    hash_chain,
    hash_chain_layers,
    new_secret,
    point_add,
    point_mul,
    pubkey,
    sign,
    verify,
)


# ---------------------------------------------------------------------------
# 1. 伪造签名
# ---------------------------------------------------------------------------


def test_forged_signature_is_rejected() -> None:
    """攻击者用另一把私钥签名，冒充 TP 的背书 —— 必须验签失败。"""
    tp_sk = new_secret()
    tp_pk = pubkey(tp_sk)

    attacker_sk = new_secret()
    forged = sign(attacker_sk, b"PHC::issue")

    assert not verify(tp_pk, b"PHC::issue", forged)


def test_signature_is_not_malleable() -> None:
    """改 s、改 R、改消息，任何一种篡改都必须让验签失败。"""
    sk = new_secret()
    pk = pubkey(sk)
    sig = sign(sk, b"PHC::issue")

    tampered_s = sig.__class__(R=sig.R, s=(sig.s + 1) % N)
    assert not verify(pk, b"PHC::issue", tampered_s)

    tampered_r = sig.__class__(R=point_mul(7), s=sig.s)
    assert not verify(pk, b"PHC::issue", tampered_r)


def test_nonce_reuse_leaks_private_key() -> None:
    """（反面教材）同一 nonce 签两条消息会直接暴露私钥。

    这不是"攻击失败"，而是证明**为什么** k 必须每次独立取样。
    测试通过 = 我们能用两条签名复原出 sk，从而确认这个风险真实存在。
    """
    sk = new_secret()
    pk = pubkey(sk)
    k = 123456789

    m1, m2 = b"msg-one", b"msg-two"
    s1 = sign(sk, m1, k=k)
    s2 = sign(sk, m2, k=k)

    # e 可公开计算，于是 sk = (s1 − s2) / (e1 − e2)
    from crypto.primitives.schnorr import challenge

    e1 = challenge(s1.R, pk, m1)
    e2 = challenge(s1.R, pk, m2)
    recovered = (s1.s - s2.s) * pow(e1 - e2, -1, N) % N

    assert pubkey(recovered) == pk, "nonce 复用应当暴露私钥 —— 故生产环境禁止固定 nonce"


# ---------------------------------------------------------------------------
# 2. 变色龙哈希：陷门不可伪造
# ---------------------------------------------------------------------------


def test_chameleon_collision_requires_trapdoor() -> None:
    """没有陷门的一方，无法为任意新消息找碰撞。"""
    key = ChameleonKey()
    ch = ChameleonHash(key)

    m1, r1 = 42, ch.rand()
    h1 = ch.compute(m1, r1)

    # 没有陷门，只能暴力猜 r'；在 2^256 空间里不可能命中
    found = False
    for guess in range(1, 500):
        if ch.compute(999, r1 + guess) == h1:
            found = True
            break
    assert not found, "无陷门不应能找到碰撞"


def test_chameleon_trapdoor_holder_can_forge() -> None:
    """对照实验：持有陷门的一方确实可以改内容而保持哈希值不变。"""
    key = ChameleonKey()
    ch = ChameleonHash(key)
    m, r = 7, ch.rand()
    h = ch.compute(m, r)

    for new_m in (11, 22, 33):
        m, r = ch.forge((m, r), new_m)
        assert ch.compute(m, r) == h


# ---------------------------------------------------------------------------
# 3. 代码篡改
# ---------------------------------------------------------------------------


def test_tampered_module_fails_cmi_check() -> None:
    """攻击者偷偷改了某个模块的代码 —— 重算 CMI 必须与原承诺不一致。"""
    modules = [b"<code:memory>", b"<code:planner>", b"<code:tooling>"]
    cmi_original = hash_chain(modules)

    tampered = list(modules)
    tampered[1] = b"<code:planner-MALICIOUS>"
    assert hash_chain(tampered) != cmi_original


def test_hash_chain_reordering_is_detected() -> None:
    """只调换顺序（不改内容）也必须被检出 —— 承诺对顺序敏感。"""
    a = [b"x", b"y", b"z"]
    b = [b"y", b"x", b"z"]
    assert hash_chain(a) != hash_chain(b)


def test_partial_chain_divergence_is_locatable() -> None:
    """逐层值能定位到第几个模块开始不一致 —— 用于故障定位与增量校验。"""
    a = hash_chain_layers([b"a", b"b", b"c"])
    b = hash_chain_layers([b"a", b"bX", b"c"])
    div = next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
    assert div == 1


# ---------------------------------------------------------------------------
# 4. 监管因子：单方无法还原身份
# ---------------------------------------------------------------------------


def _blind_wrap(pa: Paillier, identity_hash: int, rho: int) -> tuple[int, int]:
    """TP 把身份哈希封进 RF，AP 再叠加一个只有自己知道的盲因子 ρ。

    还原公式： H(ID) = Dec(RF) − ρ
    因此任一方单独行动都拿不到 H(ID)。
    """
    rf = pa.encrypt((identity_hash + rho) % pa.n)
    return rf, rho


def test_single_party_cannot_reveal_identity() -> None:
    """只有 TP 的私钥（没有 AP 的 ρ）时，解出来的不是真实身份哈希。"""
    pa = Paillier(2048)
    idh = int.from_bytes(hashlib.sha256(b"victim-id").digest(), "big")
    rho = 987654321

    rf, _ = _blind_wrap(pa, idh, rho)
    tp_alone = pa.decrypt(rf)

    assert tp_alone != idh, "TP 单独解密不应得到真实身份哈希"
    assert (tp_alone - rho) % pa.n == idh, "拿到 AP 的 ρ 之后才能还原"


def test_collaborative_reveal_works() -> None:
    """对照实验：TP 解密 + AP 提供 ρ → 正确还原。"""
    pa = Paillier(2048)
    idh = int.from_bytes(hashlib.sha256(b"victim-id").digest(), "big")
    rho = 13579

    rf, rho_ap = _blind_wrap(pa, idh, rho)
    revealed = (pa.decrypt(rf) - rho_ap) % pa.n
    assert revealed == idh


# ---------------------------------------------------------------------------
# 5. 凭证重放 / 版本回滚
# ---------------------------------------------------------------------------


def test_stale_commitment_is_detectable() -> None:
    """用旧的 CMI 冒充当前版本 —— 与最新承诺比对即暴露。"""
    v1 = hash_chain([b"<code:planner-v1>"])
    v2 = hash_chain([b"<code:planner-v2>"])
    current = v2

    assert v1 != current, "旧版本承诺不得与当前版本一致"
