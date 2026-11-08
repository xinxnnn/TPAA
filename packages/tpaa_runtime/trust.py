"""AG2 个人智能体运行时的可信层：身份声明、运行证明、协同信封。

PHC v3 是静态凭证，只回答"这个凭证由谁签发、绑定了哪组模块"。智能体真正运行起来，
还需要回答三件事，每件由不同的签名方负责，互不替代：

    DidBinding          TP 签   "这个 did:wba 就是这张 PHC 的主体"
                                （PHC 里只有 CDID 密文，第三方无法自己确认 DID↔PHC）
    RuntimeAttestation  AP 签   "这个进程按这张 PHC + 这份 manifest 构建，会话公钥是 X"
                                （AP 用自己的 D4 构建记录核对 CMI / AFRef / 模块清单）
    Envelope            会话密钥签 "这条协同消息出自上面那个进程"
                                （会话密钥随运行证明一起过期，不复用 TP/AP 长期密钥）

对端只用 TP / AP 公钥和吊销状态就能独立验完整条链，不需要回调签发方。
签名/验签只经 crypto.sdk.v1（guard R2）。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

import crypto.sdk

from .manifest import AgentManifest, Capability, ToolDeclaration, build_manifest, manifest_digest_of

v1 = crypto.sdk.v1


class TrustError(PermissionError):
    """身份 / 运行证明 / 信封不成立。message 说明具体哪一项没过。"""


def later(now: str, seconds: int) -> str:
    """ISO-8601 加秒；协议里时间统一是 YYYY-MM-DDTHH:MM:SS，字符串序即时间序。"""
    return (datetime.fromisoformat(now) + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def short(value: str, keep: int = 10) -> str:
    """长标识（did:wba 带 CSCID 密文，约 4KB）只用于展示的缩写。比对一律用全文。"""
    return value if len(value) <= 2 * keep + 1 else f"{value[:keep]}…{value[-keep:]}"


def did_label(did: str) -> str:
    """did:wba:<CSCID>:<domain1>:<domain2> → did:wba:<摘要>:<domain1>:<domain2>。"""
    parts = did.split(":")
    if len(parts) != 5:
        return short(did)
    return f"did:wba:{v1.json_digest(parts[2])[:12]}:{parts[3]}:{parts[4]}"


def phc_digest(phc_doc: dict) -> str:
    return v1.json_digest(phc_doc)


def _check(pk, sig: str, tag: str, body: dict, what: str) -> None:
    try:
        v1.check_sig(pk, sig, tag, v1.json_digest(body), what=what)
    except v1.ProtocolError as exc:
        raise TrustError(str(exc)) from exc


# ---------------------------------------------------------------------------
# 三份签名声明
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedStatement:
    body: dict
    sig: str

    def to_json(self) -> dict:
        return {"body": self.body, "sig": self.sig}


def tp_bind_did(*, tp_hsm, did: str, phc_doc: dict, now: str, ttl: int = 86400) -> SignedStatement:
    """TP：解开 DID 里的 CSCID，核对其中的 AF 就是这张 PHC 的 TPM.AF，再签 DidBinding。

    只有 TP 能打开 CSCID（R1 同一把钥匙），所以"DID 属于哪张 PHC"只能由 TP 来声明。
    """
    try:
        af, _rf = v1.tp.tp_open_did(tp_hsm=tp_hsm, did=did)
    except (v1.ProtocolError, v1.PkeError, ValueError) as exc:
        raise TrustError(f"TP 无法解析该 DID：{exc}") from exc
    phc = v1.from_jsonld(phc_doc)
    if af != phc.tpm.af:
        raise TrustError("DID 中封存的 AF 与 PHC.TPM.AF 不一致：DID 不属于这张 PHC")
    body = {"kind": "tpaa/did-binding", "did": did, "phcDigest": phc_digest(phc_doc),
            "phcVersion": phc.version, "afRef": phc.apm.af_ref, "iat": now, "exp": later(now, ttl)}
    return SignedStatement(body, v1.sign(tp_hsm, "RT/DidBinding", v1.json_digest(body)))


def ap_attest_runtime(*, ap_hsm, ap_record, phc_doc: dict, manifest: AgentManifest,
                      session_pk_hex: str, now: str, ttl: int = 3600) -> SignedStatement:
    """AP：用自己的 D4 构建记录核对 PHC 与 manifest，确认后为本次会话签运行证明。

    核对的是"AP 当初按这组模块、给这个 AF 构建过"——manifest 想多挂一个模块、
    或者拿别人的 PHC 来套，都会在这里被拒。
    """
    phc = v1.from_jsonld(phc_doc)
    if phc.apid.hex() != v1.pk_hex(ap_hsm.pubkey()):
        raise TrustError("PHC 不是本 AP 签发的")
    if phc.apm.cmi != ap_record.cmi or phc.apm.af_ref != v1.af_ref(ap_record.af.af):
        raise TrustError("PHC.APM 与 AP 构建记录不一致")
    built = [(m, v, d) for m, v, d in ap_record.modules]
    if [(m, v, d) for m, v, d in manifest.modules] != built:
        raise TrustError("manifest 的模块清单与 AP 构建记录不一致")
    if manifest.cmi != phc.apm.cmi or manifest.owner_af_ref != phc.apm.af_ref:
        raise TrustError("manifest 的 CMI / AFRef 与 PHC 不一致")
    if manifest.phc.credential_digest != phc_digest(phc_doc):
        raise TrustError("manifest 绑定的 PHC 摘要不对")
    manifest.validate()
    body = {"kind": "tpaa/runtime-attestation", "did": manifest.did,
            "phcDigest": phc_digest(phc_doc), "manifestDigest": manifest.digest(),
            "cmi": manifest.cmi, "afRef": manifest.owner_af_ref,
            "tools": sorted(t.id for t in manifest.tools), "framework": "ag2",
            "sessionPk": session_pk_hex, "iat": now, "exp": later(now, ttl)}
    return SignedStatement(body, v1.sign(ap_hsm, "RT/Attestation", v1.json_digest(body)))


# ---------------------------------------------------------------------------
# 身份卡与本地运行身份
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentCard:
    """对外出示的公开材料。不含 H(ID)、r_bind、会话私钥。"""
    did: str
    phc: dict
    manifest: dict
    binding: SignedStatement
    attestation: SignedStatement

    @property
    def session_pk(self) -> str:
        return self.attestation.body["sessionPk"]


@dataclass
class RuntimeIdentity:
    """进程内身份：公开卡片 + 只在本进程里的会话签名密钥。"""
    card: AgentCard
    manifest: AgentManifest
    session_hsm: Any
    seen_nonces: set[str] = field(default_factory=set)
    pending_replies: dict[str, str] = field(default_factory=dict)   # 请求 nonce → 对端 DID

    @property
    def did(self) -> str:
        return self.card.did

    def summary(self) -> dict:
        """给 LLM / 界面看的身份摘要。"""
        return {"did": did_label(self.did), "phcVersion": self.card.phc["version"],
                "cmi": short(self.manifest.cmi, 8),
                "tools": [t.id for t in self.manifest.tools],
                "attestationExp": self.card.attestation.body["exp"]}


@dataclass
class StatusRegistry:
    """policy-service 吊销状态的本地视图：启动前和每次工具调用前都查。"""
    revoked: dict[str, str] = field(default_factory=dict)

    def revoke(self, did: str, reason: str) -> None:
        self.revoked[did] = reason

    def check(self, did: str) -> None:
        if did in self.revoked:
            raise TrustError(f"DID 已吊销：{self.revoked[did]}")


@dataclass
class TrustContext:
    """验证方需要的全部信任根：TP / AP 公钥、吊销状态、时钟。"""
    tp_pk: Any
    ap_pk: Any
    status: StatusRegistry
    clock: Callable[[], str]


def verify_card(card: AgentCard, trust: TrustContext) -> None:
    """对端核验一张身份卡。任一项不过即抛 TrustError。"""
    now = trust.clock()
    trust.status.check(card.did)
    phc = v1.from_jsonld(card.phc)
    errs = v1.verify_public(phc, tp_pk=trust.tp_pk, ap_pk=trust.ap_pk)
    if errs:
        raise TrustError("PHC 公开校验未通过：" + "；".join(errs))
    if phc.version < 3 or not phc.tpm.cdid or not phc.apm.cmi:
        raise TrustError("PHC 尚未完成 D6（没有 CDID / CMI），不能运行")

    b, a = card.binding.body, card.attestation.body
    _check(trust.tp_pk, card.binding.sig, "RT/DidBinding", b, "TP DidBinding")
    if b["did"] != card.did or b["phcDigest"] != phc_digest(card.phc) or b["exp"] <= now:
        raise TrustError("DidBinding 与身份卡不符或已过期")

    _check(trust.ap_pk, card.attestation.sig, "RT/Attestation", a, "AP 运行证明")
    if a["did"] != card.did or a["phcDigest"] != phc_digest(card.phc) or a["exp"] <= now:
        raise TrustError("运行证明与身份卡不符或已过期")
    if a["cmi"] != phc.apm.cmi or a["afRef"] != phc.apm.af_ref:
        raise TrustError("运行证明的 CMI / AFRef 与 PHC 不一致")

    m = card.manifest
    if manifest_digest_of(m) != a["manifestDigest"]:
        raise TrustError("manifest 被改过（摘要与运行证明不一致）")
    if m["did"] != card.did or m["build"]["cmi"] != phc.apm.cmi or m["ownerBinding"]["afRef"] != phc.apm.af_ref:
        raise TrustError("manifest 绑定的 DID / CMI / AFRef 与 PHC 不一致")


# ---------------------------------------------------------------------------
# 启动：钱包核对技能承诺 → TP 绑定 DID → 组 manifest → AP 运行证明
# ---------------------------------------------------------------------------


def wallet_check_cmi(*, hid: int, modules: list[tuple[str, str, str]], phc_doc: dict) -> str:
    """钱包用自己的 H(ID) 重算 CMI（式 8）。运行时加载的模块被替换，这里就对不上。"""
    cmi = v1.hcgen(modules, hid)
    if cmi != v1.from_jsonld(phc_doc).apm.cmi:
        raise TrustError("本地模块重算的 CMI 与 PHC 不一致：技能包被替换或版本不符")
    return cmi


def assemble_manifest(*, did: str, phc_doc: dict, tp_issuer: str,
                      modules: list[tuple[str, str, str]], capabilities: list[Capability],
                      tools: list[ToolDeclaration], policy: dict | None = None,
                      created_at: str) -> AgentManifest:
    """manifest 的身份字段全部取自 PHC，不由运行时自己编。"""
    phc = v1.from_jsonld(phc_doc)
    return build_manifest(did=did, phc_digest=phc_digest(phc_doc), issuer=tp_issuer,
                          af_ref=phc.apm.af_ref, modules=modules, capabilities=capabilities,
                          tools=tools, cmi=phc.apm.cmi, policy=policy, created_at=created_at)


def start_runtime(*, did: str, phc_doc: dict, manifest: AgentManifest, tp_hsm, ap_hsm,
                  ap_record, trust: TrustContext) -> RuntimeIdentity:
    """为一次会话生成会话密钥，取得 TP / AP 两份声明，自检后返回运行身份。

    本地演示里 TP / AP 是同进程对象；真实部署这是两次跨域请求。
    """
    trust.status.check(did)
    now = trust.clock()
    session_hsm = v1.make_demo_hsm(domain="AP")         # 会话密钥：随进程生灭，不落盘
    binding = tp_bind_did(tp_hsm=tp_hsm, did=did, phc_doc=phc_doc, now=now)
    attestation = ap_attest_runtime(ap_hsm=ap_hsm, ap_record=ap_record, phc_doc=phc_doc,
                                    manifest=manifest, session_pk_hex=v1.pk_hex(session_hsm.pubkey()),
                                    now=now)
    card = AgentCard(did=did, phc=phc_doc, manifest=manifest.to_json(),
                     binding=binding, attestation=attestation)
    verify_card(card, trust)                            # 自检：对端会做的，本地先做一遍
    return RuntimeIdentity(card=card, manifest=manifest, session_hsm=session_hsm)


# ---------------------------------------------------------------------------
# 协同信封
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    body: dict
    sig: str
    sender_card: AgentCard


def seal_message(sender: RuntimeIdentity, *, to_did: str, scope: str, payload: dict,
                 now: str, ttl: int = 120, reply_to: str | None = None) -> Envelope:
    body = {"from": sender.did, "to": to_did, "scope": scope, "payload": payload,
            "nonce": secrets.token_hex(12), "iat": now, "exp": later(now, ttl),
            "attestation": v1.json_digest(sender.card.attestation.to_json()),
            "replyTo": reply_to}
    sig = v1.sign(sender.session_hsm, "RT/Envelope", v1.json_digest(body))
    if reply_to is None:
        sender.pending_replies[body["nonce"]] = to_did
    return Envelope(body=body, sig=sig, sender_card=sender.card)


def open_message(receiver: RuntimeIdentity, env: Envelope, trust: TrustContext) -> dict:
    """接收方逐项核验信封：身份卡 → 会话签名 → 收件人 / 时效 / 重放 → 入站策略。"""
    b = env.body
    if b["to"] != receiver.did:
        raise TrustError("信封不是发给本智能体的")
    if b["from"] != env.sender_card.did:
        raise TrustError("信封发送方与所附身份卡不一致")
    verify_card(env.sender_card, trust)
    if b["attestation"] != v1.json_digest(env.sender_card.attestation.to_json()):
        raise TrustError("信封引用的运行证明不是所附的这一份")
    try:
        v1.check_sig(v1.pk_from_hex(env.sender_card.session_pk), env.sig, "RT/Envelope",
                     v1.json_digest(b), what="信封")
    except v1.ProtocolError as exc:
        raise TrustError(f"{exc}（内容被篡改或不是该会话密钥所签）") from exc
    if b["exp"] <= trust.clock():
        raise TrustError("信封已过期")
    if b["nonce"] in receiver.seen_nonces:
        raise TrustError("重放：该信封已处理过")

    if b["replyTo"] is not None:
        if receiver.pending_replies.get(b["replyTo"]) != b["from"]:
            raise TrustError("不是本智能体发出的请求的应答")
        receiver.pending_replies.pop(b["replyTo"])
    else:
        rules = receiver.manifest.policy.get("inbound", {})
        allowed = rules.get(b["scope"])
        if allowed is None:
            raise TrustError(f"本智能体不对外提供 scope={b['scope']}")
        if allowed != "any-verified" and b["from"] not in allowed:
            raise TrustError(f"发送方未获授权访问 scope={b['scope']}")
    receiver.seen_nonces.add(b["nonce"])
    return b["payload"]


__all__ = ["TrustError", "SignedStatement", "AgentCard", "RuntimeIdentity", "StatusRegistry",
           "TrustContext", "Envelope", "tp_bind_did", "ap_attest_runtime", "verify_card",
           "wallet_check_cmi", "assemble_manifest", "start_runtime", "seal_message",
           "open_message", "later", "short", "did_label", "phc_digest"]
