"""AG2 Manifest v1：把 PHC 身份、CMI 构建承诺和工具权限组合成可启动的模板。

设计边界：
    PHC / DID 证明"是谁"；CMI / BuildDigest 证明"由什么构成"；
    Manifest / ToolPolicy 证明"允许做什么"。三者不能互相替代。

这个模块不做密码学内部实现：摘要使用标准库 SHA-256，CMI 通过 crypto.sdk.v1.hcgen。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

import crypto.sdk

v1 = crypto.sdk.v1


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class PhcBinding:
    profile: str
    credential_digest: str
    issuer: str
    status_version: int = 0


@dataclass(frozen=True)
class Capability:
    id: str
    version: str
    purpose: str
    input_types: tuple[str, ...] = ()
    output_types: tuple[str, ...] = ()
    risk_level: str = "low"
    requires_confirmation: bool = False
    network_access: bool = False
    memory_access: str = "none"

    def to_json(self) -> dict:
        return {
            "id": self.id, "version": self.version, "purpose": self.purpose,
            "inputTypes": list(self.input_types), "outputTypes": list(self.output_types),
            "riskLevel": self.risk_level, "requiresConfirmation": self.requires_confirmation,
            "networkAccess": self.network_access, "memoryAccess": self.memory_access,
        }


@dataclass(frozen=True)
class ToolDeclaration:
    id: str
    capability_id: str
    description: str
    risk_level: str = "low"
    requires_confirmation: bool = False
    allowed_operations: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "id": self.id, "capabilityId": self.capability_id,
            "description": self.description, "riskLevel": self.risk_level,
            "requiresConfirmation": self.requires_confirmation,
            "allowedOperations": list(self.allowed_operations),
        }


@dataclass
class AgentManifest:
    manifest_version: str
    agent_type: str
    agent_version: int
    did: str
    phc: PhcBinding
    owner_af_ref: str
    capabilities: list[Capability] = field(default_factory=list)
    tools: list[ToolDeclaration] = field(default_factory=list)
    conversation: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)
    connectors: list[dict[str, Any]] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict)
    modules: list[tuple[str, str, str]] = field(default_factory=list)
    dependencies: list[dict[str, str]] = field(default_factory=list)
    cmi: str = ""
    build_digest: str = ""
    previous_manifest_digest: str = ""
    created_at: str = ""

    def _build_payload(self) -> dict:
        return {
            "manifestVersion": self.manifest_version,
            "agentType": self.agent_type,
            "agentVersion": self.agent_version,
            "did": self.did,
            "phc": {
                "profile": self.phc.profile, "credentialDigest": self.phc.credential_digest,
                "issuer": self.phc.issuer, "statusVersion": self.phc.status_version,
            },
            "ownerBinding": {"afRef": self.owner_af_ref, "identityBinding": "phc"},
            "capabilities": [x.to_json() for x in self.capabilities],
            "tools": [x.to_json() for x in self.tools],
            "conversation": self.conversation,
            "policy": self.policy,
            "memory": self.memory,
            "connectors": self.connectors,
            "runtime": self.runtime,
            "build": {
                "modules": [{"id": m, "version": v, "digest": d} for m, v, d in self.modules],
                "dependencies": self.dependencies, "cmi": self.cmi,
                "buildDigest": self.build_digest,
            },
            "audit": {"createdAt": self.created_at, "previousManifestDigest": self.previous_manifest_digest},
        }

    def canonical_json(self) -> bytes:
        return json.dumps(self._build_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    def to_json(self) -> dict:
        payload = self._build_payload()
        payload["audit"]["manifestDigest"] = self.digest()
        return payload

    def validate(self) -> None:
        if self.manifest_version != "ag2-manifest-v1":
            raise ManifestError("不支持的 AG2 manifest 版本")
        if self.phc.profile != "tpaa_v1":
            raise ManifestError("AG2 必须绑定 tpaa_v1 PHC")
        if not self.did or not self.phc.credential_digest or not self.owner_af_ref:
            raise ManifestError("缺少 DID / PHC digest / AFRef 绑定")
        if not self.modules or not self.cmi or not self.build_digest:
            raise ManifestError("缺少 modules / CMI / buildDigest")
        capability_ids = {x.id for x in self.capabilities}
        for tool in self.tools:
            if tool.capability_id not in capability_ids:
                raise ManifestError(f"工具 {tool.id} 引用了未声明能力 {tool.capability_id}")
        for connector in self.connectors:
            if "secretRef" not in connector.get("auth", {}):
                raise ManifestError("连接器只能使用 secretRef，不得把 API 密钥写入 manifest")


def build_manifest(*, did: str, phc_digest: str, issuer: str, af_ref: str,
                   modules: list[tuple[str, str, str]], capabilities: list[Capability],
                   tools: list[ToolDeclaration], dependencies: list[dict[str, str]] | None = None,
                   conversation: dict[str, Any] | None = None,
                   connectors: list[dict[str, Any]] | None = None,
                   created_at: str = "demo", cmi: str | None = None,
                   policy: dict[str, Any] | None = None) -> AgentManifest:
    """从已验 PHC 与 AP 模块仓库构造 manifest，并计算 CMI/buildDigest。

    cmi：传入时直接采用 PHC.APM.CMI（真实签发链路，H(ID) 只在钱包/AP 手里）；
         不传时用 DID 摘要代替 H(ID) 算一个本地演示值。
    policy：合并进默认策略（如协同入站白名单）。
    """
    if not modules:
        raise ManifestError("至少需要一个模块")
    if cmi is None:
        hid_material = int.from_bytes(hashlib.sha256(did.encode()).digest(), "big")
        cmi = v1.hcgen(modules, hid_material)
    draft = AgentManifest(
        manifest_version="ag2-manifest-v1", agent_type="personal-agent", agent_version=1,
        did=did, phc=PhcBinding("tpaa_v1", phc_digest, issuer), owner_af_ref=af_ref,
        capabilities=capabilities, tools=tools,
        conversation=conversation or {"systemPromptRef": "local:ag2-default", "maxTurns": 20},
        policy={"denyUnknownTools": True, "denyPrivateDataToTools": True, **(policy or {})},
        memory={"mode": "session", "userOptInRequired": True}, connectors=connectors or [],
        runtime={"preflightRequired": True, "statusCheck": "before_start_and_tool_call"},
        modules=modules, dependencies=dependencies or [], created_at=created_at,
    )
    draft.cmi = cmi
    draft.build_digest = hashlib.sha256(draft.canonical_json()).hexdigest()
    draft.validate()
    return draft


def manifest_digest_of(data: dict) -> str:
    """对端拿到的是 manifest JSON：去掉 audit.manifestDigest 后按同一规范化重算摘要。"""
    payload = json.loads(json.dumps(data))
    payload.get("audit", {}).pop("manifestDigest", None)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


__all__ = ["ManifestError", "PhcBinding", "Capability", "ToolDeclaration", "AgentManifest",
           "build_manifest", "manifest_digest_of"]
