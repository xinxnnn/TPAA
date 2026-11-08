"""localstore 的目录契约（ARCHITECTURE §7.1 的可执行版本）。

    根目录
    ├── modules/<module_id>/<version>/      模块代码（内容寻址 + manifest），只读
    ├── agents/<agent_id>/                  实例：meta / selection / cmi / build / versions / state
    ├── index/by-identity.enc                H(ID) → agent_id 列表（**唯一**含身份映射的文件，必须加密）
    ├── index/by-owner-did.json              owner_did → agent_id 列表（均为 DID，不含身份明文）
    └── recycle/<agent_id>/                 软删实例，保留恢复窗口

★ 路径推导全部集中在这里的一个函数里，别处不许自己拼目录。

    派生链的坑：agent_id 直接等于 DID 的主干，而子体 DID 又是「父 DID 的派生段」。
    若按 DID 主干拼目录，`did:...:L1` 会落进 `did:...` 的目录内部，子体一删就把父体带走。
    所以 agents/ 下用**扁平编码**：DID 主干里的 `:` 与 `%` 转义成 `-` 与 `%25`，
    任何 DID 都只能映射到一层文件名。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


class StoreLayoutError(ValueError):
    """ID / DID 不合法 —— 多半是想借路径穿越跳出存储根。"""


def encode_agent_id(did: str) -> str:
    """DID → 单层目录名（可逆、无分隔符、无上跳）。

    `did:wba:ROOT:pa.example` → `did-wba-ROOT-pa.example`
    `did:wba:ROOT:pa.example:sub-1` → `did-wba-ROOT-pa.example-sub-1`
    两者互不为前缀关系里的「目录包含」，因为都落在同一层。
    """
    if not did or any(c.isspace() for c in did):
        raise StoreLayoutError(f"非法 DID：{did!r}")
    if not did.startswith("did:"):
        raise StoreLayoutError(f"DID 必须以 did: 开头：{did!r}")
    # 至少四段：did:<method>:<namespace>:<identifier>；`did:` / `did:..` 之类都不能落盘
    if len([s for s in did.split(":") if s]) < 3:
        raise StoreLayoutError(f"DID 结构不完整：{did!r}")
    out = did.replace("%", "%25").replace(":", "-")
    if out in {".", ".."} or "/" in out or "\\" in out:
        raise StoreLayoutError(f"DID 编码后仍不安全：{did!r} → {out!r}")
    return out


class Layout:
    """一个存储根的路径推导器。所有读写方法只经由它拿路径。"""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # ---- 顶层 ----
    @property
    def modules(self) -> Path:
        return self.root / "modules"

    @property
    def agents(self) -> Path:
        return self.root / "agents"

    @property
    def index_dir(self) -> Path:
        return self.root / "index"

    @property
    def recycle(self) -> Path:
        return self.root / "recycle"

    @property
    def identity_index(self) -> Path:
        return self.index_dir / "by-identity.enc"

    @property
    def owner_index(self) -> Path:
        return self.index_dir / "by-owner-did.json"

    # ---- 模块 ----
    def module_dir(self, module_id: str, version: str) -> Path:
        _safe_seg(module_id)
        _safe_seg(version)
        return self.modules / module_id / version

    # ---- 实例 ----
    def agent_dir(self, did: str) -> Path:
        return self.agents / encode_agent_id(did)

    def agent_meta(self, did: str) -> Path:
        return self.agent_dir(did) / "meta.json"

    def agent_selection(self, did: str) -> Path:
        return self.agent_dir(did) / "selection.json"

    def agent_cmi(self, did: str) -> Path:
        return self.agent_dir(did) / "cmi.json"

    def agent_versions(self, did: str) -> Path:
        return self.agent_dir(did) / "versions.json"

    def agent_build(self, did: str, version: int | str) -> Path:
        _safe_seg(str(version))
        return self.agent_dir(did) / "build" / str(version)

    def agent_state_dir(self, did: str) -> Path:
        return self.agent_dir(did) / "state"

    # ---- 回收 ----
    def recycled(self, did: str) -> Path:
        return self.recycle / encode_agent_id(did)

    # ---- 建目录 ----
    def ensure_base(self) -> None:
        for d in (self.modules, self.agents, self.index_dir, self.recycle):
            d.mkdir(parents=True, exist_ok=True)


def _safe_seg(seg: str) -> None:
    if not seg or seg in {".", ".."} or "/" in seg or "\\" in seg:
        raise StoreLayoutError(f"非法路径段：{seg!r}")


# ---------------------------------------------------------------------------
# 原子写：先落同目录临时文件再 replace —— 中途崩溃不会留下半截 JSON
# ---------------------------------------------------------------------------


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


__all__ = ["Layout", "StoreLayoutError", "encode_agent_id", "write_atomic"]
