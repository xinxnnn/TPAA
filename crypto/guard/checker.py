"""crypto/guard —— 越权静态检查卡口（红线 2 的可强制实现）。

规则：
  R1  密码学原语层 `crypto.primitives` 只允许被 `crypto/` 内部使用；
      任何 `crypto/` 之外的文件 import 它即越权。
  R2  密码层内部实现 `crypto.phc / crypto.derivation / crypto.envelope`
      只允许被 `crypto/` 内部使用；上层业务只能经 `crypto.hsm` / `crypto.sdk`。
  R3  `crypto/` 之外的业务代码不得自行实现加密（启发式：自建 encrypt/decrypt
      或引入第三方密码库）。
  R4  陷门碰撞 `.forge(...)`（TPCH/APCH）与 `collide_r(...)`（tpaa_v1 的 AF/CCH）
      各自只允许出现在两个白名单文件里；其余位置一律违规。
      这是红线 1（陷门不出 HSM）最后一个可静态验证的收口：
      连 `crypto/` 内部的其他文件也没有资格碰陷门。

豁免：
  * `crypto/` 目录自身（它本就是密码层）
  * `tests/` 目录（验证层有权访问内部以证明性质）
  * 虚拟环境 / 依赖目录（.venv / venv / node_modules / __pycache__）
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

# 原语层：最底层，仅 crypto 内部可用
_PRIMITIVE_MODULES = {
    "crypto.primitives", "crypto.primitives.group", "crypto.primitives.schnorr",
    "crypto.primitives.paillier", "crypto.primitives.chameleon",
    "crypto.primitives.hashchain",
}
# 密码层内部实现：上层不得直接使用
_INTERNAL_PREFIXES = ("crypto.phc", "crypto.derivation", "crypto.envelope", "crypto.tpaa_v1")
# 允许的上层入口
_ALLOWED_MODULES = {"crypto.hsm", "crypto.sdk"}
# 受检的业务代码根
_BUSINESS_ROOTS = {"services", "apps", "localstore", "wallet"}
# R1/R2/R3 的豁免目录（首段命中即整文件跳过）
_EXEMPT_DIRS = {"crypto", "tests", "demos", ".venv", "venv", "node_modules", "__pycache__"}
# R4 的豁免目录 —— 注意**不含 crypto**，也**不含 demos**：
# 密码层恰恰是 R4 的重点管辖范围，crypto/ 内部也只有两个白名单文件能碰陷门；
# 演示脚本会被人抄走当样板使用，同样没有资格绕过这条收口。
_R4_EXEMPT_DIRS = {"tests", ".venv", "venv", "node_modules", "__pycache__"}

# R3 启发式：业务代码里出现这些，视为自建加密
_R3_PATTERNS = [
    (r"def\s+encrypt\s*\(", "encrypt"),
    (r"def\s+decrypt\s*\(", "decrypt"),
    (r"from\s+cryptography\s+import", "cryptography"),
    (r"import\s+Crypto\b", "pycryptodome"),
]

# R4 白名单：每个"求陷门碰撞"的调用名，只允许出现在各自的两个文件里
_TRAPDOOR_CALLS = {
    "forge": {                              # proto0 / v1 共用的 TPCH/APCH 变色龙哈希
        "crypto/primitives/chameleon.py",   # 定义处（含 PublicChameleon 的拒绝分支）
        "crypto/hsm/soft.py",               # 唯一的真机调用：chameleon_collide 内部
    },
    "collide_r": {                          # tpaa_v1 的 AF 定制变色龙哈希（CCH）
        "crypto/tpaa_v1/cch.py",            # 定义处
        "crypto/hsm/v1.py",                 # 唯一的真机调用：cch_collide 内部
    },
}
_FORGE_WHITELIST = _TRAPDOOR_CALLS["forge"]   # 保留旧名，测试与文档仍在引用


@dataclass
class Violation:
    rule: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path}: {self.detail}"


def _module_of(node: ast.AST) -> str:
    if isinstance(node, ast.Import):
        return node.names[0].name
    if isinstance(node, ast.ImportFrom):
        return node.module or ""
    return ""


def _inside_crypto(parts: tuple[str, ...]) -> bool:
    return bool(parts) and parts[0] == "crypto"


def _check_forge(tree: ast.Module, relpath: str) -> list[Violation]:
    """R4：陷门碰撞 `.forge(...)` 只能出现在白名单文件里。

    用 AST 而非正则 —— 否则文档里大量出现的"forge"一词会被误判成调用。
    `collide_r` 既可能以属性（cch.collide_r）也可能以裸名（from-import 后）调用，两种都抓。
    """
    out: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
        if name == "forge" and not isinstance(f, ast.Attribute):
            continue                          # 只有 .forge( 算陷门调用（沿用原规则）
        allowed = _TRAPDOOR_CALLS.get(name)
        if allowed is None or relpath in allowed:
            continue
        files = " 与 ".join(sorted(allowed))
        hsm_api = "HSM.chameleon_collide()" if name == "forge" else "V1SoftHSM.cch_collide()"
        out.append(Violation(
            "R4", relpath,
            f"陷门碰撞 {name}( 只允许出现在 {files}；需要改写内容请走 {hsm_api}"))
    return out


def scan_text(text: str, relpath: str) -> list[Violation]:
    """对单文件源码做越权检查。relpath 决定豁免与业务归属。"""
    parts = Path(relpath).parts
    head = parts[0] if parts else ""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []  # 语法错误交给真正的 linter，不在此负责

    # ★ R4 先跑，且管辖范围包含 crypto/：密码层自己也没有资格到处碰陷门
    violations: list[Violation] = (
        _check_forge(tree, relpath) if head not in _R4_EXEMPT_DIRS else []
    )

    if head in _EXEMPT_DIRS:
        return violations

    in_business = bool(parts) and parts[0] in _BUSINESS_ROOTS
    inside_crypto = _inside_crypto(parts)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        mod = _module_of(node)
        # R1：越权 import 原语层
        if mod in _PRIMITIVE_MODULES or mod.startswith("crypto.primitives."):
            if not inside_crypto:
                violations.append(Violation(
                    "R1", relpath,
                    f"越权 import 原语层 {mod}（仅 crypto/ 内部可用）"))
        # ★ R2 先判、且是**前缀**判：`from crypto.sdk import x`
        #   解析出的 module 恰好等于 "crypto.sdk"；若先走白名单（等值）判断，
        #   "crypto.sdk.phc" 这类子模块就会被放行 —— 那个"唯一入口"等于没有边界。
        #   只放行 `import crypto.sdk`（包级导入），from-import 一律不许：
        #   包级导入拿不到任何具体函数，后续只能走属性访问，边界才看得见。
        elif mod == "crypto.sdk" or mod.startswith("crypto.sdk."):
            bare_ok = (
                isinstance(node, ast.Import)
                and any(a.name == "crypto.sdk" and a.asname is None for a in node.names)
            )
            if not inside_crypto and not bare_ok:
                violations.append(Violation(
                    "R2", relpath,
                    "经 sdk 必须 `import crypto.sdk` 后用属性访问，"
                    "不得 from-import 把入口捕进本模块"))
        elif any(mod == p or mod.startswith(p + ".") for p in _INTERNAL_PREFIXES):
            if not inside_crypto:
                violations.append(Violation(
                    "R2", relpath,
                    f"越权 import 密码层内部实现 {mod}（上层应经 crypto.hsm / crypto.sdk）"))
        elif mod in _ALLOWED_MODULES:
            continue  # 允许的入口，跳过

    # R3：业务代码自建加密
    if in_business:
        for pat, label in _R3_PATTERNS:
            if re.search(pat, text):
                violations.append(Violation(
                    "R3", relpath,
                    f"业务代码中疑似自建加密：{label}（应使用 crypto/sdk）"))
    return violations


def scan_dir(root: str | Path) -> list[Violation]:
    """扫描整个项目，返回全部越权违规。"""
    root = Path(root)
    out: list[Violation] = []
    for p in root.rglob("*.py"):
        rel = p.relative_to(root).as_posix()
        out.extend(scan_text(p.read_text(encoding="utf-8", errors="replace"), rel))
    return out
