"""端口（Ports）：agent-service 依赖外部什么。

为什么要单独建这一层、而不是直接 import 别的服务：
    本服务是「请求方」，TP 那边（phc-service / did-service）与 IPFS 那边都是**别的责任方**。
    请求方不能假设对方怎么实现，只能声明「我需要你给我这几样东西」。
    于是换实现（本地演练 / 内网 gRPC / 真实 IPFS 网关）不用改一行用例代码，
    也才能证明「AP 侧不持有 TP 私钥」这件事在结构上成立、而不是靠自觉。

三个端口：

    CapabilityPort   向 TP 要：签发 PHC、封 DID、验 PHC（TP 的 HSM 只在他那边转）
    ContentPort      向 IPFS 要：按 CID 取件；以及把 CID 换成 ECID 交给 TP 封
    Clock            时间。抽出来是为了让 TTL / 冻结时间在测试里可控

★ 端口签名里**没有任何密钥参数**。这不是巧合：上层拿不到私钥，就没有能力越权；
  想越权只能先改端口定义，而那一步会在 review 里被看见。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# ---- 交给 TP 的「公开材料」：跨域只能给这些 ----


@dataclass(frozen=True)
class PublicKeyMaterial:
    """TP 签发/校验所需的全部公开材料。

    注意它**不含任何私钥或陷门**：AP 只在本地 HSM 里持有自己的陷门，
    连"自己那一半"的能力都不外借 —— TP 只需要能算出 APCH，不需要能改写它。
    """

    ap_pubkey_hex: str            # AP 的 Schnorr 公钥（压缩点十六进制）
    ap_chameleon_cpk_hex: str     # AP 的变色龙公钥
    tp_pubkey_hex: str            # 供 AP 侧事后校验用（TP 的公钥本就是公开的）
    tp_chameleon_cpk_hex: str


@dataclass(frozen=True)
class IssueRequest:
    """D4 之前的第一步：请 TP 签发初始 PHC。

    ★ `parent_did` 必须在这一步就给（主体传空串）。
      AF 在签发时就按它算定，事后补写必然导致「AF 锚定不一致」，
      而且主体永远碰不到这个坑（parent_did 恒为空），只有派生时才暴露。
    """

    identity_hash: int
    tau: int
    crf: int
    apid_hex: str
    ap: PublicKeyMaterial
    requested_at: str
    parent_did: str = ""


@dataclass(frozen=True)
class IssueResult:
    phc_json: dict                 # PHC 的 JSON-LD 形态（跨域交换的唯一形态）
    ecid: str                      # 加密后的内容标识符，写进 PHC.TPM.ECID
    phi_ref: str                   # TP 侧存根编号（本题不用，留给审计串联）


@dataclass(frozen=True)
class SealDidRequest:
    phc_json: dict
    parent_did: str                # 主智能体为空串
    did_namespace: str             # 由 TP 的 did-service 决定，AP 不指定具体 DID
    ap: PublicKeyMaterial
    requested_at: str


@dataclass(frozen=True)
class SealDidResult:
    did: str                       # TP 给的唯一 DID（子体亦唯一，不与父体共用）
    phc_json: dict                 # 已写入 CDID 并重签
    lineage_proof: dict = field(default_factory=dict)


@dataclass(frozen=True)
class WriteCmiRequest:
    """算法1：AP 把 CMI 写进自己那半（APM），**不需要 TP 参与**。

    ★ 为什么它被放进 `CapabilityPort` 这个"对 TP 的端口"里：
      这是本方案里唯一一个「看起来该找对方、实际必须自己做」的动作。
      CMI 写进 APM 要靠 APCH 的陷门求碰撞，而陷门只在 AP 的 HSM 里 ——
      TP 拿着 APCH 的公钥算得出值、改不了内容（这正是路线 A 的设计意图）。
      所以这个端口的语义应读作「涉及 PHC 变更的能力动作」，
      而不是「向 TP 发起的请求」：算法1 落在这里，恰好让
      「TP 全程不参与算法1」在代码结构上成立。
    """

    phc_json: dict
    cmi: str                      # 配置承诺（64 位十六进制）
    apm_time: str                 # 配置冻结的时间戳
    requested_at: str


@dataclass(frozen=True)
class PhcVerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


@runtime_checkable
class CapabilityPort(Protocol):
    """对 TP 的三件事 + AP 自己的一件（算法1）。"""

    def issue_phc(self, req: IssueRequest) -> IssueResult: ...

    def seal_did(self, req: SealDidRequest) -> SealDidResult: ...

    def write_cmi(self, req: WriteCmiRequest) -> dict:
        """算法1。返回更新后的 PHC JSON。调用方须自证 APCH/TPCH/AF 未变。"""
        ...

    def verify_phc(self, phc_json: dict, *, identity_hash: int,
                   tau: int, crf: int) -> PhcVerifyResult: ...


# ---- 内容层：IPFS ----


@dataclass(frozen=True)
class StoredContent:
    cid: str
    payload: bytes


@runtime_checkable
class ContentPort(Protocol):
    """IPFS 第五方的两个动作：按 CID 取件、把内容存进去。"""

    def fetch(self, cid: str) -> StoredContent: ...

    def put(self, payload: bytes) -> str:
        """返回 CID。CID 本身**不得明文落 localstore**（红线 17）。"""
        ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> str:
        """ISO 8601 时间戳（秒级）。"""
        ...

    def plus_hours(self, hours: int) -> str:
        """从现在起 n 小时之后的时间戳（TTL 用）。"""
        ...


__all__ = [
    "PublicKeyMaterial", "IssueRequest", "IssueResult",
    "SealDidRequest", "SealDidResult", "PhcVerifyResult",
    "CapabilityPort", "ContentPort", "Clock", "StoredContent",
]
