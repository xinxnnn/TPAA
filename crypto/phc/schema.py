"""PHC（人格凭证）结构 —— 对齐说明书表1 与 PPT 第 7 页的四段结构。

    ASO.TPM   仅 TP 可写（Time / CDID / AF / ECID）
    ASO.APM   AP 经授权后可写（Time / CMI）
    TPA       TP 的背书（TPid + TPproof）
    APA       AP 的背书（APid + APproof）
    PROOF     整体完整性（TPCH / APCH / CHproof / VM）

核心设计（这是整套方案成立的关键）：

    AF   = CH_TP( H(ID) ‖ τ ‖ CRF ‖ APCH ‖ parent_did )
    APCH = CH_AP( APM ‖ APA )
    CHproof = Sign_TP( TPCH ‖ APCH )

AP 改 APM 时，用自己的陷门求碰撞 → APCH **取值不变**
    → AF 的消息内容不变 → AF 取值不变
    → TP 当初对 (TPCH‖APCH) 的签名继续有效，且 TP 全程不需要参与。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..primitives.group import N, ser_point


def _h(*parts) -> int:
    """把任意字段混合成一个群标量（哈希到 [1, N)）。"""
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, bytes):
            pass
        elif isinstance(p, tuple):
            p = ser_point(p)
        elif isinstance(p, str):
            p = p.encode("utf-8")
        else:
            # int / bool 等一律先转成十进制字符串再编码，保证跨语言一致
            p = str(p).encode("utf-8")
        h.update(p)
    return int.from_bytes(h.digest(), "big") % N or 1


@dataclass
class PHC:
    """人格凭证。哈希字段以整数存放，序列化时转十六进制。"""

    version: int = 1

    # ---- ASO.TPM：仅 TP 可写 ----
    tpm_time: str = ""
    tpm_cdid: str = ""       # 智能体 DID（D6 之后才填）
    tpm_af: int = 0          # 锚定因子 AF
    tpm_af_r: int = 0        # AF 的变色龙随机数（公开值，安全性不依赖其保密）
    tpm_ecid: str = ""       # 加密的内容标识符

    # ---- ASO.APM：AP 经授权后可写 ----
    apm_time: str = ""
    apm_cmi: str = ""        # 模块哈希链承诺 CMI（十六进制）

    # ---- TPA：TP 背书 ----
    tpa_tpid: bytes = b""
    tpa_proof: bytes = b""

    # ---- APA：AP 背书 ----
    apa_apid: bytes = b""
    apa_proof: bytes = b""

    # ---- PROOF：整体完整性 ----
    proof_tpch: int = 0
    proof_tpch_r: int = 0
    proof_apch: int = 0
    proof_apch_r: int = 0
    proof_chproof: bytes = b""
    proof_vm: str = "Schnorr-secp256k1 / ChameleonHash-secp256k1"

    # ---- 派生关系：子智能体才有 ----
    parent_did: str = ""

    # =====================================================================
    # 参与哈希的消息
    # =====================================================================

    def tpm_message(self) -> int:
        return _h(self.tpm_time, self.tpm_cdid, self.tpm_af, self.tpm_ecid)

    def tpa_message(self) -> int:
        return _h(self.tpa_tpid, self.tpa_proof)

    def apm_message(self) -> int:
        return _h(self.apm_time, self.apm_cmi)

    def apa_message(self) -> int:
        return _h(self.apa_apid, self.apa_proof)

    def tpch_message(self) -> int:
        """TPCH 覆盖 TPM 与 TPA —— 由 TP 陷门保护。"""
        return _h(self.tpm_message(), self.tpa_message())

    def apch_message(self) -> int:
        """APCH 覆盖 APM 与 APA —— 由 AP 陷门保护。"""
        return _h(self.apm_message(), self.apa_message())

    def signed_digest(self) -> bytes:
        """CHproof 签的是 TPCH 与 APCH 的拼接。"""
        return f"{self.proof_tpch}|{self.proof_apch}".encode()

    def af_message(self, identity_hash: int, tau: int, crf: int) -> int:
        return _h(identity_hash, tau, crf, self.proof_apch, self.parent_did)

    # =====================================================================
    # 序列化
    # =====================================================================

    def to_jsonld(self) -> dict:
        return {
            "@context": "https://tpaa.example/credentials/personhood/v1",
            "version": self.version,
            "ASO": {
                "TPM": {
                    "Time": self.tpm_time,
                    "CDID": self.tpm_cdid,
                    "AF": hex(self.tpm_af),
                    "AF_r": hex(self.tpm_af_r),
                    "ECID": self.tpm_ecid,
                },
                "APM": {"Time": self.apm_time, "CMI": self.apm_cmi},
            },
            "TPA": {"TPid": self.tpa_tpid.hex(), "TPproof": self.tpa_proof.hex()},
            "APA": {"APid": self.apa_apid.hex(), "APproof": self.apa_proof.hex()},
            "PROOF": {
                "TPCH": hex(self.proof_tpch),
                "TPCH_r": hex(self.proof_tpch_r),
                "APCH": hex(self.proof_apch),
                "APCH_r": hex(self.proof_apch_r),
                "CHproof": self.proof_chproof.hex(),
                "VM": self.proof_vm,
            },
            "parentDid": self.parent_did,
        }

    @classmethod
    def from_jsonld(cls, doc: dict) -> "PHC":
        """JSON-LD → PHC。跨域交换之后要能把它读回来再验。

        ★ 补这个方向的原因：
          只有 `to_jsonld()` 时，拿到 PHC 的服务只能"转发"、不能"校验"，
          而校验恰好是唯一能证明对方没改过内容的动作 —— 没有反序列化，
          验签就只能发生在签发者自己的心里。
        ★ 只做结构转换、不做任何校验：
          伪造或畸形的字段要能原样读进来，然后在校验环节得到"校验失败"这个
          明确结论，而不是在读的时候抛一个解析异常（那会把"被篡改"伪装成"格式错误"）。
        """
        aso = doc.get("ASO", {}) or {}
        tpm = aso.get("TPM", {}) or {}
        apm = aso.get("APM", {}) or {}
        tpa = doc.get("TPA", {}) or {}
        apa = doc.get("APA", {}) or {}
        proof = doc.get("PROOF", {}) or {}
        return cls(
            version=int(doc.get("version", 1)),
            tpm_time=str(tpm.get("Time", "")),
            tpm_cdid=str(tpm.get("CDID", "")),
            tpm_af=int(tpm.get("AF", "0"), 16),
            tpm_af_r=int(tpm.get("AF_r", "0"), 16),
            tpm_ecid=str(tpm.get("ECID", "")),
            apm_time=str(apm.get("Time", "")),
            apm_cmi=str(apm.get("CMI", "")),
            tpa_tpid=bytes.fromhex(tpa.get("TPid", "") or ""),
            tpa_proof=bytes.fromhex(tpa.get("TPproof", "") or ""),
            apa_apid=bytes.fromhex(apa.get("APid", "") or ""),
            apa_proof=bytes.fromhex(apa.get("APproof", "") or ""),
            proof_tpch=int(proof.get("TPCH", "0"), 16),
            proof_tpch_r=int(proof.get("TPCH_r", "0"), 16),
            proof_apch=int(proof.get("APCH", "0"), 16),
            proof_apch_r=int(proof.get("APCH_r", "0"), 16),
            proof_chproof=bytes.fromhex(proof.get("CHproof", "") or ""),
            proof_vm=str(proof.get("VM", "Schnorr-secp256k1 / ChameleonHash-secp256k1")),
            parent_did=str(doc.get("parentDid", "") or ""),
        )
