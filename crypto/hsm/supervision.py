"""监管密钥句柄 —— 追溯链 R1（Paillier 解密）的密钥形态（红线 1）。

R1 要做的事：TP 在申领时把 H(ID) 用**监管公钥**加密成 CSCID 存起来，
立案之后才解开。这条链上有一个别的 HSM 管不到的东西 —— Paillier 密钥对。
它不能是裸的 p/q 满天飞，否则红线 1 在追溯这一段就破了。

所以这里对 Paillier 复刻 SoftHSM 的纪律：

    SupervisionKey     持有完整��钥对 —— 只在监管域内生成与使用，
                       对外只暴露 `public()` 与 `open()`
    SupervisionPublic  只持 n —— 只能 seal，open 直接拒绝，
                       被 pickle/传输后天然降级（根本没有可泄的字段）

一个与 SoftHSM 相同的细节：`SupervisionKey.__getstate__` 剥掉一切私钥材料。
序列化后的对象只剩 n —— 它能继续加密，永远不能解密。
"""

from __future__ import annotations

from secrets import randbelow

from ..primitives.paillier import Paillier


class SupervisionPublic:
    """监管公钥形态。可以跨域传递：它只能封存，不能还原。"""

    def __init__(self, n: int) -> None:
        self.n = n
        self.nsq = n * n
        self.g = n + 1

    def seal(self, m: int) -> int:
        """把明文整数封成 CSCID。可用监管公钥的人人都能做这一步。"""
        if not 0 <= m < self.n:
            raise ValueError("明文必须小于 n")
        r = randbelow(self.n - 1) + 1
        return pow(self.g, m, self.nsq) * pow(r, self.n, self.nsq) % self.nsq

    def open(self, _c: int) -> int:
        raise PermissionError(
            "公钥形态没有解密能力 —— 还原 H(ID) 必须由监管域持有 SupervisionKey")


class SupervisionKey:
    """监管密钥：生成一次、注入 supervision-service、永不外传。"""

    def __init__(self, bits: int = 2048, *, seed: bytes | None = None) -> None:
        if bits < 2048:
            raise ValueError("监管 Paillier 至少 2048 bit —— 演示可显式放宽，但默认不许")
        self._pae = Paillier(bits, seed=seed)

    def public(self) -> SupervisionPublic:
        # 降级后仍要能取公钥：验算/封存是公开动作，失去的只有解密权
        n = self._pae.n if self._pae is not None else self._degraded_n
        return SupervisionPublic(n)

    def open(self, cscid: int) -> int:
        """解密只在监管域内发生 —— 这是「立案之后才还原身份」的技术执行点。"""
        if self._pae is None:
            raise PermissionError(
                "该密钥已被序列化降级，不再持有解密能力 —— "
                "还原 H(ID) 只能在监管域内用原始密钥完成")
        return self._pae.decrypt(cscid)

    # ---- 红线 1：私钥不得随对象被导出 ----
    def __getstate__(self) -> dict:
        if self._pae is None:
            return {"n": self._degraded_n}
        return {"n": self._pae.n}

    def __setstate__(self, state: dict) -> None:
        self._pae = None  # type: ignore[assignment]
        self._degraded_n = state.get("n")

    def private_key_present(self) -> bool:
        return self._pae is not None


__all__ = ["SupervisionKey", "SupervisionPublic"]
