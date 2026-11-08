"""build/ 的确定性组装（ARCHITECTURE §7.1「制品可重建」的可执行版本）。

**确定性是承诺的一部分**：
    同一份 selection + 同一批模块，任何时候重放都必须得到**逐字节相同**的 build。
    做不到「确定性」，找回就只能算「大概能跑」，那不是承诺，是安慰。

因此这里写文件时：
    * 文件清单按路径排序后写入（不依赖 OS 的目录遍历顺序）
    * agent.yaml 里的字段固定顺序、不做任何"加个时间戳吧"的小聪明
    * 不写入版本号以外的运行态信息

`build_manifest.json` 里记录每个文件的 sha256 —— 它是"build 是否被重放过"的证据。
build 可以在磁盘上重建，但它的**内容**一旦生成就不该变；变了说明 selection 或模块变了。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class BuildPlan:
    files: dict[str, bytes]      # 相对路径 → 内容
    manifest: dict               # 写进 build_manifest.json 的内容

    def build_digest(self) -> str:
        """整个 build 的摘要：按路径排序后逐文件混合。"""
        h = hashlib.sha256()
        for rel in sorted(self.files):
            h.update(rel.encode())
            h.update(b"\0")
            h.update(self.files[rel])
            h.update(b"\0")
        return h.hexdigest()


def assemble(
    *,
    did: str,
    agent_type: str,
    parent_did: str,
    modules: list[tuple[str, str, bytes]],   # (module_id, version, 源码)
    cmi: str,
    layer_chains: list[str],
    ecid: str,
    version: int,
) -> BuildPlan:
    """按固定规则组装 build 制品。同样的输入 → 同样的字节。"""
    modules = sorted(modules, key=lambda m: (m[0], m[1]))
    bundle: dict[str, bytes] = {}
    for mid, ver, src in modules:
        # 目录名带版本号：升级后新旧两份可以并存，回滚才有的可回
        bundle[f"bundle/{mid}/{ver}/__init__.py"] = src

    agent_yaml = _render_agent_yaml(
        did=did, agent_type=agent_type, parent_did=parent_did,
        modules=[(m[0], m[1]) for m in modules],
        cmi=cmi, ecid=ecid, version=version,
    ).encode()

    integrity = json.dumps({
        "did": did,
        "version": version,
        "cmi": cmi,
        "layers": list(layer_chains),
        "ecid": ecid,                 # ★ 只有 ECID，没有 CID（红线 17）
        "bundleDigest": _digest_bundle(bundle),
    }, ensure_ascii=False, indent=2, sort_keys=True).encode()

    files = {"agent.yaml": agent_yaml, "integrity.json": integrity, **bundle}
    manifest = {
        "files": {rel: _h(data) for rel, data in sorted(files.items())},
        "buildDigest": hashlib.sha256(
            b"".join(rel.encode() + b"\0" + _h(files[rel]).encode() + b"\0"
                     for rel in sorted(files))
        ).hexdigest(),
    }
    return BuildPlan(files=files, manifest=manifest)


def _digest_bundle(bundle: dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for rel in sorted(bundle):
        h.update(rel.encode())
        h.update(b"\0")
        h.update(bundle[rel])
    return h.hexdigest()


def _render_agent_yaml(
    *,
    did: str,
    agent_type: str,
    parent_did: str,
    modules: list[tuple[str, str]],
    cmi: str,
    ecid: str,
    version: int,
) -> str:
    """手写 YAML —— 不引第三方库，字段顺序固定，方便人眼审。

    ★ 这里**不出现任何密钥**：agent.yaml 会进 git、会被拷进制品，
      它只写「phc_ref: 指向哪一份 PHC」和「用哪些模块」。
      真正能签名的能力在 runtime 里由域内 HSM 提供（ARCHITECTURE 18.6）。
    """
    lines = [
        "apiVersion: tpaa.example/v1",
        "kind: Agent",
        "metadata:",
        f"  did: {did}",
        f"  agentType: {agent_type}",
        f"  parentDid: {parent_did or 'null'}",
        "spec:",
        f"  phcRef: phc/{did}.json",       # 引用，不是拷贝
        f"  ecid: {ecid}",
        "  modules:",
    ]
    for mid, ver in modules:
        lines.append(f"    - id: {mid}")
        lines.append(f"      version: {ver}")
    lines += [
        "  integrity:",
        f"    cmi: {cmi}",
        f"    version: {version}",
        "runtime:",
        "  framework: ag2",
        "  capability: domain-hsm",       # 能力来自域内 HSM，不来自文件
    ]
    return "\n".join(lines) + "\n"


def selection_digest(items: list[tuple[str, str]]) -> str:
    """selection 的稳定摘要 —— 与 domain.entities.digest_selection 口径一致。"""
    h = hashlib.sha256()
    for mid, ver in sorted(items):
        h.update(f"{mid}@{ver}\n".encode())
    return h.hexdigest()


__all__ = ["BuildPlan", "assemble", "selection_digest"]
