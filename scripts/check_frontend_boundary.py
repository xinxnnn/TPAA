#!/usr/bin/env python3
"""前端边界静态卡口（步骤 8）—— ARCHITECTURE.md §10 网络策略的可强制实现。

后端有 crypto/guard 管「上层不得自行实现加密」；这里是它的前端对应物，
把四条前端红线变成 CI 里能拦下来的规则：

  F1  前端不碰密码学：不得引入加密库、不得调用 SubtleCrypto、不得出现密钥材料标识符
  F2  区隔离：某区前端不得出现其他区的 API 前缀（跨域只能走后端 coordination）
  F3  会话不落盘持久化：不得把会话/凭据写进 localStorage
  F4  shared 保持中立：不得出现 BASE_URL 或任何 /api 字面量

用法：
    python scripts/check_frontend_boundary.py [frontend_dir]
    # 退出码 0 = 无违规；1 = 发现违规
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SRC_SUFFIXES = {".ts", ".tsx", ".js", ".jsx"}

# app -> 本区 API 前缀
ZONE_PREFIX = {
    "user-web": "/api/user",
    "tp-web": "/api/tp",
    "ap-web": "/api/ap",
    "ops-web": "/api/ops",
}
ALL_PREFIXES = set(ZONE_PREFIX.values())

# ---- F1：前端不碰密码学 ----
F1_IMPORTS = re.compile(
    r"""^\s*(?:import\s+[^'"]*?from\s*|import\s*|const\s+\w+\s*=\s*require\s*\(\s*)"""
    r"""['"](node:crypto|crypto|crypto-js|tweetnacl|jsrsasign|jsencrypt|libsodium[^'"]*|forge)['"]""",
    re.M,
)
F1_SUBTLE = re.compile(r"(crypto|window\.crypto|globalThis\.crypto)\s*\.\s*subtle", re.I)
F1_SECRET_IDENT = re.compile(
    r"\b(privateKey|private_key|secretKey|mnemonic|seedPhrase|passphrase|apiSecret)\b"
)

# ---- F2：其他区前缀 ----
ANY_PREFIX = re.compile(r"/api/(user|tp|ap|ops)\b")

# ---- F3：localStorage 落盘 ----
F3_LOCAL = re.compile(r"\blocalStorage\s*\.\s*setItem")

# ---- 注释剥离 ----
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")


@dataclass(frozen=True)
class Violation:
    rule: str
    path: str
    line: int
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path}:{self.line} — {self.detail}"


def _strip_comments(src: str) -> str:
    """去掉注释，避免把说明文字里出现的字样误判成代码。"""
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", src))


def _iter_files(app_dir: Path):
    for p in sorted(app_dir.rglob("*")):
        if not p.is_file() or p.suffix not in SRC_SUFFIXES:
            continue
        rel = p.relative_to(app_dir).parts
        # 只扫 per-app 源码树，忽略 dist / node_modules / 非源码目录
        if any(part in {"node_modules", "dist", "build", ".vite"} for part in rel):
            continue
        yield p


def _rel(p: Path, root: Path) -> str:
    """相对根显示路径；根不一致时退回绝对路径（检查器可扫任意目录）。"""
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def _check_app(app: str, app_dir: Path, root: Path) -> list[Violation]:
    own = ZONE_PREFIX.get(app)
    out: list[Violation] = []

    for p in _iter_files(app_dir):
        rel = _rel(p, root)
        src = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        lines = src.splitlines()

        for i, line in enumerate(lines, start=1):
            m = F1_IMPORTS.search(line)
            if m:
                out.append(Violation("F1", rel, i, f"前端禁止引入加密库 '{m.group(1)}'（密码学只在后端 crypto.sdk 内）"))
            if F1_SUBTLE.search(line):
                out.append(Violation("F1", rel, i, "前端禁止调用 SubtleCrypto（加解密不得在浏览器侧发生）"))
            if F1_SECRET_IDENT.search(line):
                out.append(Violation("F1", rel, i, "前端不得出现密钥材料标识符（私钥/助记词/口令种子）"))

            if own:
                pm = ANY_PREFIX.search(line)
                if pm and pm.group(0) != own:
                    out.append(
                        Violation(
                            "F2", rel, i,
                            f"{app} 只允许访问 {own}，不得出现其他区前缀 '{pm.group(0)}'"
                            "（跨域请走后端 coordination）",
                        )
                    )

            if F3_LOCAL.search(line):
                out.append(Violation("F3", rel, i, "会话/凭据禁止写入 localStorage（应用 sessionStorage）"))

    # api-client 必须存在且 BASE_URL 落在本区
    client = app_dir / "src" / "services" / "api-client.ts"
    if not client.exists():
        out.append(Violation("F5", app, 0, "缺少 src/services/api-client.ts（后端访问的唯一出口）"))
    elif own and f"'{own}'" not in client.read_text(encoding="utf-8"):
        out.append(Violation("F5", _rel(client, root), 0,
                             f"BASE_URL 未声明为 '{own}'"))

    return out


def _ALL_LITERAL_PREFIXES(line: str) -> list[str]:
    return ANY_PREFIX.findall(line)


def _check_shared(shared: Path, root: Path) -> list[Violation]:
    """F4：shared 保持中立——不得出现 BASE_URL 或任何 /api 字面量。"""
    out: list[Violation] = []
    if not shared.exists():
        return out
    for p in sorted(shared.rglob("*")):
        if not p.is_file() or p.suffix not in SRC_SUFFIXES:
            continue
        rel = _rel(p, root)
        src = _strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        for i, line in enumerate(src.splitlines(), start=1):
            if "BASE_URL" in line:
                out.append(Violation("F4", rel, i,
                                     "shared 不得定义 BASE_URL（区划属属于各 App，不得下沉）"))
            pm = ANY_PREFIX.search(line)
            if pm:
                out.append(Violation("F4", rel, i,
                                     f"shared 不得出现区前缀 '{pm.group(0)}'"))
    return out


def check(root: Path = ROOT / "apps") -> list[Violation]:
    """扫描整个 frontend/，返回全部违规（按规则、路径排序）。"""
    violations: list[Violation] = []
    for app in sorted(ZONE_PREFIX):
        app_dir = root / app
        if app_dir.is_dir():
            violations.extend(_check_app(app, app_dir, root))
    violations.extend(_check_shared(root / "shared", root))
    return sorted(violations, key=lambda v: (v.rule, v.path, v.line))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]).resolve() if argv else (ROOT / "apps")
    violations = check(root)
    if not violations:
        print(f"frontend boundary OK — 0 violations ({root})")
        return 0
    print(f"frontend boundary FAILED — {len(violations)} violations", file=sys.stderr)
    for v in violations:
        print(str(v), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
