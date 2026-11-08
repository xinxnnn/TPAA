"""modules/ —— 平台模块仓库（AP 侧上架流程写入，全局只读）。

为什么是「模块共享、实例轻量」：
    模块是平台通用能力，不涉密；内容相同即去重（content-addressed）。
    实例目录只存选择向量与组装产物，找回时重放选择向量再取模块即可。
    这样 localstore 的增量成本随「实例数」而非「实例数 × 模块数」增长。

完整性用什么锚？**用模块内容本身**。
    manifest.json 里记录每个文件的 sha256 与整体 digest，digest 同时决定版本号。
    这里刻意不引密码层：模块仓库的自校验只需要普通哈希，属于「存储完整性」而非
    「协议承诺」；协议层面的 CMI 由 agent-service 经 crypto.sdk 计算后写进 PHC，
    两套东西各自的信任根不同，别混在一起。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .paths import Layout, StoreLayoutError, _safe_seg


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ModuleEntry:
    """上架产物：一个模块 + 一个版本号。"""

    module_id: str
    version: str
    digest: str
    files: dict[str, str]        # 相对路径 → sha256
    description: str = ""
    revoked: bool = False


class ModuleRepo:
    """模块的发布与读取。

    发布是幂等的：同一模块、同一内容重复上架只落一份；内容变了必须换版本号（禁止原地改写）。
    """

    def __init__(self, layout: Layout) -> None:
        self.layout = layout

    # ---- 发布 ----
    def publish(
        self,
        module_id: str,
        version: str,
        files: dict[str, bytes],
        *,
        description: str = "",
    ) -> ModuleEntry:
        _safe_seg(module_id)
        _safe_seg(version)
        if not files:
            raise ValueError("模块至少要有一个文件")

        target = self.layout.module_dir(module_id, version)
        if target.exists():
            existing = self.get_entry(module_id, version)
            incoming = self._digest_of(files)
            if existing.digest != incoming:
                raise StoreLayoutError(
                    f"模块 {module_id}@{version} 已存在且内容不同 —— "
                    "上架流程不允许原地改写版本，请发布新版本号"
                )
            return existing

        manifest_files: dict[str, str] = {}
        for rel, data in files.items():
            rel_posix = Path(rel).as_posix()
            if rel_posix.startswith("..") or "/../" in rel_posix:
                raise StoreLayoutError(f"模块文件路径越界：{rel!r}")
            p = target / rel_posix
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            manifest_files[rel_posix] = _sha256(data)

        digest = self._digest_of(files)
        manifest = {
            "moduleId": module_id,
            "version": version,
            "digest": digest,
            "description": description,
            "files": manifest_files,
            "revoked": False,
        }
        (target / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        self._mark_readonly(target)
        return self.get_entry(module_id, version)

    # ---- 读取 ----
    def get_entry(self, module_id: str, version: str) -> ModuleEntry:
        mpath = self.layout.module_dir(module_id, version) / "manifest.json"
        if not mpath.exists():
            raise FileNotFoundError(f"模块不存在：{module_id}@{version}")
        m = json.loads(mpath.read_text(encoding="utf-8"))
        return ModuleEntry(
            module_id=m["moduleId"], version=m["version"], digest=m["digest"],
            files=m["files"], description=m.get("description", ""),
            revoked=bool(m.get("revoked", False)),
        )

    def read_file(self, module_id: str, version: str, relpath: str) -> bytes:
        """取单个文件，并核对其 sha256 与 manifest 一致。"""
        entry = self.get_entry(module_id, version)
        rel = Path(relpath).as_posix()
        if rel not in entry.files:
            raise FileNotFoundError(f"{module_id}@{version} 不含文件 {rel}")
        p = self.layout.module_dir(module_id, version) / rel
        data = p.read_bytes()
        if _sha256(data) != entry.files[rel]:
            raise StoreLayoutError(
                f"模块文件被篡改：{module_id}@{version}/{rel}（manifest 摘要不符）")
        return data

    def verify(self, module_id: str, version: str) -> list[str]:
        """逐文件重算摘要，返回不一致项（空列表 = 完好）。modules/ 只读，正常应恒为空。"""
        entry = self.get_entry(module_id, version)
        bad: list[str] = []
        for rel, want in entry.files.items():
            p = self.layout.module_dir(module_id, version) / rel
            if not p.exists():
                bad.append(f"{rel}: 缺失")
            elif _sha256(p.read_bytes()) != want:
                bad.append(f"{rel}: 摘要不符")
        return bad

    def versions(self, module_id: str) -> list[str]:
        d = self.layout.modules / module_id
        if not d.exists():
            return []
        return sorted(p.name for p in d.iterdir() if p.is_dir())

    def revoke(self, module_id: str, version: str) -> None:
        """下架标记：只翻 manifest 里的标志位。

        **不删文件** —— 已生成实例仍能重放（找回保证 build 级无损），
        但新生成不得再引用它；是否强制升级由 lifecycle-service 决定。
        """
        mpath = self.layout.module_dir(module_id, version) / "manifest.json"
        _ensure_writable(mpath)
        m = json.loads(mpath.read_text(encoding="utf-8"))
        m["revoked"] = True
        mpath.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
        _restore_readonly(mpath)

    # ---- 内部 ----
    @staticmethod
    def _digest_of(files: dict[str, bytes]) -> str:
        h = hashlib.sha256()
        for rel in sorted(files):
            h.update(Path(rel).as_posix().encode())
            h.update(b"\0")
            h.update(files[rel])
            h.update(b"\0")
        return h.hexdigest()

    @staticmethod
    def _mark_readonly(root: Path) -> None:
        """尽力置只读（Windows 上目录属性语义有限，Unix 上是真权限）。"""
        try:
            for p in [root, *root.rglob("*")]:
                if p.is_file():
                    p.chmod(p.stat().st_mode & ~0o222)
        except OSError:
            pass


def digest_files(files: Iterable[tuple[str, bytes]]) -> str:
    """外部复算用：同样的排序规则，便于对账。"""
    return ModuleRepo._digest_of(dict(files))


def _ensure_writable(p: Path) -> None:
    """modules/ 平时只读；下架这类管理动作要临时放开写位（Windows 也只读属性挡得住）。"""
    try:
        p.chmod(p.stat().st_mode | 0o200)
    except OSError:
        pass


def _restore_readonly(p: Path) -> None:
    try:
        p.chmod(p.stat().st_mode & ~0o222)
    except OSError:
        pass


__all__ = ["ModuleRepo", "ModuleEntry", "digest_files"]
