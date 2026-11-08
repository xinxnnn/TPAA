"""PHC v1 结构 —— 对外 JSON-LD 使用说明书图示的 ASO / TPA / APA / PROOF。

    ASO.TPM   Time / CDID / AF / ECID              仅 TP 写
    ASO.APM   Time / CMI / AFRef                   仅 AP 写
    TPA       TPid / TPproof = Sign_tp(TPM, TPid)
    APA       APid / APproof = Sign_ap(APM, APid)
    PROOF     TPCH / APCH / CHproof / VM

与表 1 的差别（errata）：
    + profile / version      区分 tpaa_v1 与 proto0（E-profile）
    + APM.AFRef = H(AF)      N2：防拼接。第三方没有 r，算不了 TPCH/APCH，
                             CHproof 对他只是"签了两个数"。没有 AFRef 时，
                             别人那份 APM+APproof 可以原样搬进这张凭证。
                             用 AF 而不是 TPM 的摘要：算法2 会改 TPM（写 CDID），
                             而 AF 在整个生命周期里不变，绑它才不会在 D6 后失效。
    − 所有随机数（r_tp / r_ap / r_bind）  E3：只存在各方自己的库里，不进凭证。
                             proto0 把它们公开在 PHC 里，导致 TP 能还原 AP 的陷门（K1）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .encoding import digest, encode, h_int
from ..primitives.group import N

PROFILE = "tpaa_v1"
CONTEXT = "https://tpaa.example/credentials/phc/v1"
JSONLD_CONTEXT = {"@vocab": CONTEXT + "#"}
_LEGACY_SCHEMA = "tpaa_v1_compact"
VM = "tpaa_v1: Schnorr-secp256k1 (TPproof/APproof/CHproof); CH-secp256k1 (TPCH/APCH); CCH-DL3072-percred (AF)"


@dataclass
class TPM:
    time: str = ""
    cdid: str = ""            # 原文：用户公钥加密的 DID（P3 接 ElGamal 后填）
    af: int = 0
    ecid: str = ""


@dataclass
class APM:
    time: str = ""
    cmi: str = ""
    af_ref: str = ""          # hex(H(AF))


@dataclass
class PHCv1:
    version: int = 1
    tpm: TPM = field(default_factory=TPM)
    apm: APM = field(default_factory=APM)
    tpid: bytes = b""
    tpproof: bytes = b""
    apid: bytes = b""
    approof: bytes = b""
    tpch: int = 0
    apch: int = 0
    chproof: bytes = b""
    wire_schema: str = field(default="phc-v1", repr=False, compare=False)

    # ---- 签名 / 哈希消息（全部经规范化编码，每类一个域分离 tag）----
    def tpproof_msg(self) -> bytes:
        t = self.tpm
        return encode("TPproof", t.time, t.cdid, t.af, t.ecid, self.tpid)

    def approof_msg(self) -> bytes:
        a = self.apm
        return encode("APproof", a.time, a.cmi, a.af_ref, self.apid)

    def tpch_msg(self) -> int:
        return h_int("TPCH", self.tpproof_msg(), self.tpproof, mod=N)

    def apch_msg(self) -> int:
        return h_int("APCH", self.approof_msg(), self.approof, mod=N)

    def chproof_msg(self) -> bytes:
        return encode("CHproof", self.tpch, self.apch)


def af_ref(af: int) -> str:
    return digest("AFRef", af).hex()


def _require_keys(value: object, expected: set[str], what: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"PHC {what} 必须且只能包含字段：{', '.join(sorted(expected))}")
    return value


def to_jsonld(phc: PHCv1) -> dict:
    if phc.wire_schema == _LEGACY_SCHEMA:
        return {
            "@context": CONTEXT,
            "profile": PROFILE,
            "version": phc.version,
            "agentSelfOwned": {
                "TPM": {"Time": phc.tpm.time, "CDID": phc.tpm.cdid,
                        "AF": format(phc.tpm.af, "x"), "ECID": phc.tpm.ecid},
                "APM": {"Time": phc.apm.time, "CMI": phc.apm.cmi, "AFRef": phc.apm.af_ref},
            },
            "tpAttestation": {"TPid": phc.tpid.hex(), "TPproof": phc.tpproof.hex()},
            "apAttestation": {"APid": phc.apid.hex(), "APproof": phc.approof.hex()},
            "proof": {"TPCH": format(phc.tpch, "x"), "APCH": format(phc.apch, "x"),
                      "CHproof": phc.chproof.hex(), "VM": VM},
        }
    return {
        "@context": JSONLD_CONTEXT,
        "profile": PROFILE,
        "version": phc.version,
        "ASO": {
            "TPM": {"Time": phc.tpm.time, "CDID": phc.tpm.cdid,
                    "AF": format(phc.tpm.af, "x"), "ECID": phc.tpm.ecid},
            "APM": {"Time": phc.apm.time, "CMI": phc.apm.cmi, "AFRef": phc.apm.af_ref},
        },
        "TPA": {"TPid": phc.tpid.hex(), "TPproof": phc.tpproof.hex()},
        "APA": {"APid": phc.apid.hex(), "APproof": phc.approof.hex()},
        "PROOF": {"TPCH": format(phc.tpch, "x"), "APCH": format(phc.apch, "x"),
                  "CHproof": phc.chproof.hex(), "VM": VM},
    }


def from_jsonld(d: dict) -> PHCv1:
    if not isinstance(d, dict):
        raise ValueError("PHC 必须是 JSON-LD 对象")
    if d.get("profile") != PROFILE:
        raise ValueError(f"不是 {PROFILE} 凭证（profile={d.get('profile')!r}）")
    if type(d.get("version")) is not int or d["version"] < 1:
        raise ValueError("PHC version 必须是正整数")
    canonical = {"ASO", "TPA", "APA", "PROOF"}.issubset(d)
    legacy = {"agentSelfOwned", "tpAttestation", "apAttestation", "proof"}.issubset(d)
    if canonical == legacy:
        raise ValueError("PHC 必须且只能使用 ASO/TPA/APA/PROOF 结构")
    if canonical:
        _require_keys(d, {"@context", "profile", "version", "ASO", "TPA", "APA", "PROOF"},
                      "顶层")
        aso, tpa, apa, pf = d["ASO"], d["TPA"], d["APA"], d["PROOF"]
        if d.get("@context") != JSONLD_CONTEXT:
            raise ValueError("PHC @context 与 tpaa_v1 JSON-LD 定义不一致")
        wire_schema = "phc-v1"
    else:
        _require_keys(d, {"@context", "profile", "version", "agentSelfOwned",
                          "tpAttestation", "apAttestation", "proof"}, "旧版顶层")
        aso, tpa, apa, pf = d["agentSelfOwned"], d["tpAttestation"], d["apAttestation"], d["proof"]
        if d.get("@context") != CONTEXT:
            raise ValueError("旧版 PHC @context 无效")
        wire_schema = _LEGACY_SCHEMA
    aso = _require_keys(aso, {"TPM", "APM"}, "ASO")
    t = _require_keys(aso["TPM"], {"Time", "CDID", "AF", "ECID"}, "ASO.TPM")
    a = _require_keys(aso["APM"], {"Time", "CMI", "AFRef"}, "ASO.APM")
    tpa = _require_keys(tpa, {"TPid", "TPproof"}, "TPA")
    apa = _require_keys(apa, {"APid", "APproof"}, "APA")
    pf = _require_keys(pf, {"TPCH", "APCH", "CHproof", "VM"}, "PROOF")
    if pf["VM"] != VM:
        raise ValueError("PHC PROOF.VM 与 tpaa_v1 算法定义不一致")
    return PHCv1(
        version=int(d["version"]),
        tpm=TPM(time=t["Time"], cdid=t["CDID"], af=int(t["AF"], 16), ecid=t["ECID"]),
        apm=APM(time=a["Time"], cmi=a["CMI"], af_ref=a["AFRef"]),
        tpid=bytes.fromhex(tpa["TPid"]), tpproof=bytes.fromhex(tpa["TPproof"]),
        apid=bytes.fromhex(apa["APid"]), approof=bytes.fromhex(apa["APproof"]),
        tpch=int(pf["TPCH"], 16), apch=int(pf["APCH"], 16),
        chproof=bytes.fromhex(pf["CHproof"]), wire_schema=wire_schema,
    )


__all__ = ["PROFILE", "CONTEXT", "JSONLD_CONTEXT", "VM", "TPM", "APM", "PHCv1", "af_ref",
           "to_jsonld", "from_jsonld"]
