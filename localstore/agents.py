"""agents/ —— 单个智能体实例目录的读写。

    一个实例（agents/<encoded-did>/）里有什么：

    meta.json        类型、归属、父体、状态、TTL、出生时间        ← 全部是 DID / 哈希，无身份明文
    selection.json   用户所选模块及版本（找回的**唯一输入**）    ← 制品可重建的根据
    cmi.json         配置承诺 CMI + 逐层中间值                    ← 与 PHC 里的 CMI 必须一致
    versions.json    版本链                                       ← 回滚
    build/<v>/       agent.yaml + bundle/                         ← runtime 拉起时读
    state/           会话与长期记忆（**不可重建**，不在找回保证内）

为什么要 build/ 而不在 runtime 里现拼：
    build 是确定性产物 —— 同样的 selection + modules 必须得到同样的 build。
    做不到「确定性」，找回就只能算「大概能跑」，那不是承诺。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum

from .paths import Layout, write_atomic


class AgentState(str, Enum):
    ACTIVE = "active"
    FROZEN = "frozen"      # 校验失败 / 上级被吊销 —— 保留取证价值，不删
    REVOKED = "revoked"    # 用户主动注销或追溯吊销
    RECYCLED = "recycled"  # 已移入 recycle/


class AgentType(str, Enum):
    PRIMARY = "primary"
    SUB = "sub"


@dataclass
class AgentMeta:
    did: str
    agent_type: AgentType
    owner_did: str                      # 子体的 owner_did 仍是自然人主 DID（归谁管，不是从谁派生）
    identity_hash: str                  # H(ID) 的十六进制 —— **是哈希不是身份**
    created_at: str
    parent_did: str = ""                # 仅子体
    state: AgentState = AgentState.ACTIVE
    expires_at: str = ""                # 仅子体：TTL
    ecid: str = ""                      # 加密后的内容标识符（取自 PHC.TPM.ECID）
    revoked_at: str = ""
    frozen_reason: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["agent_type"] = self.agent_type.value
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AgentMeta":
        d = dict(d)
        d["agent_type"] = AgentType(d["agent_type"])
        d["state"] = AgentState(d["state"])
        return cls(**d)


@dataclass
class Selection:
    """用户所选模块及版本 —— 找回的唯一输入。"""

    items: list[dict] = field(default_factory=list)   # [{"module_id":..., "version":...}]

    def normalized(self) -> list[dict]:
        """排序后再算 CMI —— 顺序由平台定义，不由前端传参决定，否则同一意图能算出两个 CMI。"""
        return sorted(self.items, key=lambda x: (x["module_id"], x["version"]))

    def to_dict(self) -> dict:
        return {"items": self.normalized()}

    @classmethod
    def from_dict(cls, d: dict) -> "Selection":
        return cls(items=list(d.get("items", [])))


@dataclass
class CmiRecord:
    cmi: str
    layers: list[str] = field(default_factory=list)
    computed_at: str = ""
    module_digests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CmiRecord":
        return cls(**d)


class AgentStore:
    """实例目录的读写。写入一律原子替换，避免半截 JSON。"""

    def __init__(self, layout: Layout) -> None:
        self.layout = layout

    # ---- 存在性 ----
    def exists(self, did: str) -> bool:
        return self.layout.agent_meta(did).exists()

    def load_meta(self, did: str) -> AgentMeta:
        p = self.layout.agent_meta(did)
        if not p.exists():
            raise FileNotFoundError(f"实例不存在：{did}")
        return AgentMeta.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def save_meta(self, meta: AgentMeta) -> None:
        write_atomic(self.layout.agent_meta(meta.did),
                     json.dumps(meta.to_dict(), ensure_ascii=False, indent=2).encode())

    def load_selection(self, did: str) -> Selection:
        return Selection.from_dict(
            json.loads(self.layout.agent_selection(did).read_text(encoding="utf-8")))

    def save_selection(self, did: str, sel: Selection) -> None:
        write_atomic(self.layout.agent_selection(did),
                     json.dumps(sel.to_dict(), ensure_ascii=False, indent=2).encode())

    def load_cmi(self, did: str) -> CmiRecord:
        return CmiRecord.from_dict(
            json.loads(self.layout.agent_cmi(did).read_text(encoding="utf-8")))

    def save_cmi(self, did: str, rec: CmiRecord) -> None:
        write_atomic(self.layout.agent_cmi(did),
                     json.dumps(rec.to_dict(), ensure_ascii=False, indent=2).encode())

    def load_versions(self, did: str) -> list[dict]:
        p = self.layout.agent_versions(did)
        if not p.exists():
            return []
        return json.loads(p.read_text(encoding="utf-8"))

    def append_version(self, did: str, entry: dict) -> None:
        chain = self.load_versions(did)
        chain.append(entry)
        write_atomic(self.layout.agent_versions(did),
                     json.dumps(chain, ensure_ascii=False, indent=2).encode())

    def current_version(self, did: str) -> int:
        chain = self.load_versions(did)
        return int(chain[-1]["version"]) if chain else 0

    def write_build(self, did: str, version: int, files: dict[str, bytes]) -> None:
        base = self.layout.agent_build(did, version)
        for rel, data in files.items():
            write_atomic(base / rel, data)

    def read_build(self, did: str, version: int) -> dict[str, bytes]:
        base = self.layout.agent_build(did, version)
        if not base.exists():
            raise FileNotFoundError(f"build 不存在：{did}@v{version}")
        return {
            p.relative_to(base).as_posix(): p.read_bytes()
            for p in sorted(base.rglob("*")) if p.is_file()
        }

    # ---- 状态迁移 ----
    def freeze(self, did: str, reason: str, *, at: str) -> None:
        meta = self.load_meta(did)
        meta.state = AgentState.FROZEN
        meta.frozen_reason = reason
        meta.revoked_at = at
        self.save_meta(meta)

    def revoke(self, did: str, *, at: str, reason: str = "") -> None:
        meta = self.load_meta(did)
        meta.state = AgentState.REVOKED
        meta.revoked_at = at
        meta.frozen_reason = reason
        self.save_meta(meta)

    def iter_all(self) -> list[AgentMeta]:
        out: list[AgentMeta] = []
        if not self.layout.agents.exists():
            return out
        for d in sorted(self.layout.agents.iterdir()):
            mp = d / "meta.json"
            if mp.is_file():
                out.append(AgentMeta.from_dict(
                    json.loads(mp.read_text(encoding="utf-8"))))
        return out


__all__ = ["AgentStore", "AgentMeta", "AgentState", "AgentType", "Selection", "CmiRecord"]
