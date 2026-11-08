"""tpaa_v1 的 HSM：在 SoftHSM 之上加「每张凭证一对 CCH 陷门」与 PRF（errata E1 / E2）。

密钥分用途（E2）：
    Schnorr 私钥      签名（TPproof / APproof / CHproof）         —— 继承自 SoftHSM
    变色龙私钥        TPCH / APCH 碰撞                             —— 继承自 SoftHSM
    root              派生 CCH 陷门（每个槽位一个）与 PRF 密钥     —— 本类新增
三者互相独立：解出任何一张凭证的 CCH 陷门，都推不出签名私钥。

槽位（slot）：
    allocate_slot(owner)   HSM 自己生成随机 nonce（调用方不能挑），登记归属人，
                           返回 (nonce, 陷门公钥)
    cch_collide(...)       owner 必须与登记一致；第一次碰撞时再把 nonce 绑定到 AF，
                           之后同一 nonce 只接受同一个 AF
★ 为什么要两道绑定：nonce 是公开的（要写进请求里）。没有绑定的话，
  攻击者拿受害者的 nonce 自己构造一个 AF 去请求碰撞，就能从 (r, r') 解出
  受害者那张凭证的陷门。owner 挡"抢先占用"，AF 挡"同一槽位换凭证"。
★ owner 由协议层给，且必须是**已认证**的值（TP 侧用已验签的用户公钥指纹）。
  HSM 只负责比对，不负责判断 owner 是不是真的。
⚠️ 登记表默认只在内存里；跨重启要传入持久化的 `bindings`（任意 MutableMapping）。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections.abc import MutableMapping

from ..tpaa_v1.cch import collide_r
from ..tpaa_v1.params import G, P, Q
from .soft import SoftHSM


class SlotError(PermissionError):
    """槽位不存在，或者 nonce 已经绑定到另一个 AF。"""


class V1SoftHSM(SoftHSM):
    def __init__(self, *, domain: str, root: bytes | None = None,
                 bindings: MutableMapping | None = None, **kw) -> None:
        super().__init__(domain=domain, **kw)
        self._root = root if root is not None else secrets.token_bytes(32)
        if len(self._root) < 32:
            raise ValueError("HSM root 至少 32 字节")
        self._bindings = bindings if bindings is not None else {}
        self._lock = threading.Lock()

    # ---- 内部派生（只在实例内）----
    def _derive(self, label: str, *parts: bytes) -> bytes:
        msg = label.encode() + b"\x00" + b"\x00".join(parts)
        return hmac.new(self._root, msg, hashlib.sha256).digest()

    def _trapdoor(self, nonce: str) -> int:
        if getattr(self, "_root", None) is None:
            raise PermissionError("该 HSM 已被序列化降级，不再持有 CCH 陷门")
        # 用两段 HMAC 拼成 512 bit 再取模，偏差可忽略
        raw = self._derive("cch-trapdoor", nonce.encode(), b"0") + \
            self._derive("cch-trapdoor", nonce.encode(), b"1")
        return int.from_bytes(raw, "big") % Q or 1

    # ---- 能力 ----
    def allocate_slot(self, owner: str) -> tuple[str, int]:
        """为一张新凭证分配陷门。返回 (nonce, 陷门公钥 = g^t)。"""
        if not owner:
            raise SlotError("分配槽位必须给出归属人（已认证的身份标识）")
        nonce = f"{self.domain.lower()}-{secrets.token_hex(16)}"
        with self._lock:
            self._bindings[nonce] = {"owner": owner, "af": None}
        return nonce, pow(G, self._trapdoor(nonce), P)

    def slot_public(self, nonce: str) -> int:
        if nonce not in self._bindings:
            raise SlotError(f"槽位不存在：{nonce}")
        return pow(G, self._trapdoor(nonce), P)

    def recover_slot(self, *, nonce: str, owner: str, af: int, expected_pub: int) -> int:
        """Restore a legacy slot only after its signed CR and AF have been verified."""
        public = pow(G, self._trapdoor(nonce), P)
        if public != expected_pub:
            raise SlotError(f"旧申请里的 TP 陷门公钥与槽位不符：{nonce}")
        with self._lock:
            slot = self._bindings.get(nonce)
            if slot is None:
                self._bindings[nonce] = {"owner": owner, "af": af}
            elif slot["owner"] != owner or slot["af"] not in (None, af):
                raise SlotError(f"槽位已有不同归属或 AF 绑定：{nonce}")
        return public

    def cch_collide(self, *, nonce: str, owner: str, af: int,
                    x_old: int, x_new: int, r: int) -> int:
        """在 nonce 对应的陷门上求碰撞，返回 r'。调用方负责先核验 AF 等式。"""
        with self._lock:
            slot = self._bindings.get(nonce)
            if slot is None:
                raise SlotError(f"槽位不存在：{nonce}")
            if slot["owner"] != owner:
                raise SlotError("槽位归属人不符 —— 拒绝在别人的陷门上求碰撞")
            if slot["af"] is None:
                slot["af"] = af
                self._bindings[nonce] = slot          # 让持久化映射看到这次写入
            elif slot["af"] != af:
                raise SlotError("该槽位已绑定到另一张凭证的 AF —— 拒绝在别人的陷门上求碰撞")
        return collide_r(self._trapdoor(nonce), x_old, x_new, r)

    # ---- 传输加密（说明书 EN_pk / DE_sk，ElGamal-KEM，见 tpaa_v1/pke.py）----
    def _enc_sk(self) -> int:
        if getattr(self, "_root", None) is None:
            raise PermissionError("该 HSM 已被序列化降级，不再持有解密私钥")
        raw = self._derive("enc-sk", b"0") + self._derive("enc-sk", b"1")
        return int.from_bytes(raw, "big") % Q or 1

    def enc_pub(self) -> int:
        """加密公钥 g^x（与签名公钥、陷门公钥都不是同一把，errata E2）。"""
        return pow(G, self._enc_sk(), P)

    def pke_open(self, box: dict, *, tag: str) -> dict:
        """在 HSM 内解开发给本方的密文。解密私钥不出实例。"""
        from ..tpaa_v1.pke import open_with
        return open_with(self._enc_sk(), box, tag=tag)

    def prf(self, label: str, *parts) -> int:
        """PRF(sk, ·) 的实现（式 9 的 s_ap = PRF(sk_ap, AF)）。输出 256 bit。"""
        enc = [str(p).encode() for p in parts]
        return int.from_bytes(self._derive("prf/" + label, *enc), "big")

    # ---- 红线 1：root 不随对象导出 ----
    def __getstate__(self) -> dict:
        state = super().__getstate__()
        state.pop("_root", None)
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: dict) -> None:
        super().__setstate__(state)
        self._lock = threading.Lock()

    def private_key_present(self) -> bool:
        return super().private_key_present() and getattr(self, "_root", None) is not None


__all__ = ["V1SoftHSM", "SlotError"]
