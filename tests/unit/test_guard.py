"""crypto/guard 卡口测试：越权必须被检出，合法入口必须放行。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from crypto.guard.checker import scan_dir, scan_text

ROOT = Path(__file__).resolve().parents[2]


def test_r1_primitives_outside_crypto_blocked() -> None:
    """业务层 import 原语层必须被 R1 拦截。"""
    v = scan_text("from crypto.primitives.schnorr import sign", "services/evil.py")
    assert any(x.rule == "R1" for x in v)


def test_r2_internal_outside_crypto_blocked() -> None:
    """业务层 import 密码层内部实现必须被 R2 拦截。"""
    v = scan_text("import crypto.phc", "services/evil.py")
    assert any(x.rule == "R2" for x in v)
    v2 = scan_text("from crypto.envelope import seal_secinfo", "services/evil.py")
    assert any(x.rule == "R2" for x in v2)


def test_r3_self_built_encryption_blocked() -> None:
    """业务层自建 encrypt 必须被 R3 拦截。"""
    v = scan_text("def encrypt(data, key):\n    return data", "services/evil.py")
    assert any(x.rule == "R3" for x in v)


def test_hsm_entry_allowed_in_business() -> None:
    """crypto.hsm 是允许的上层入口，不应误报。"""
    v = scan_text("from crypto.hsm import SoftHSM", "services/ok.py")
    assert not any(x.rule in ("R1", "R2") for x in v)


def test_r2_blocks_sdk_submodule_and_from_import() -> None:
    """★ sdk 的边界靠两点守住：

    1. `from crypto.sdk import x` 解析出的 module 恰好等于 "crypto.sdk" ——
       若白名单走等值判断并优先，这条就被静默放行，白名单里的前缀形同虚设；
    2. 只放行包级 `import crypto.sdk`：具体函数不得被捕进业务命名空间。
    """
    for src in ("from crypto.sdk import issue_phc",
                "import crypto.sdk.phc",
                "import crypto.sdk as s"):
        v = scan_text(src, "services/evil.py")
        assert any(x.rule == "R2" for x in v), f"应被 R2 拦下：{src}"


def test_bare_package_import_still_allowed() -> None:
    """`import crypto.sdk` + 属性访问是正常用法，不该被误伤。"""
    v = scan_text("import crypto.sdk\ncrypto.sdk.verify_phc", "services/ok.py")
    assert not any(x.rule in ("R1", "R2") for x in v)


def test_tests_exempt() -> None:
    """tests 目录豁免，可直接访问内部以验证性质。"""
    v = scan_text("from crypto.envelope import seal_secinfo", "tests/unit/x.py")
    assert v == []


def test_crypto_internal_allowed() -> None:
    """crypto 内部使用原语/内部实现是合法的。"""
    v = scan_text("from crypto.primitives.schnorr import sign", "crypto/phc/engine.py")
    assert v == []
    v2 = scan_text("from crypto.envelope import seal_secinfo", "crypto/phc/engine.py")
    assert v2 == []


# ---------------------------------------------------------------------------
# R4：陷门碰撞的位置收口（红线 1 最后一个可静态验证的点）
# ---------------------------------------------------------------------------


def test_r4_forge_in_business_blocked() -> None:
    """业务层直接求碰撞 —— R4 必须拦下。"""
    v = scan_text("new_r = ch.forge((m, r), 999)", "services/evil.py")
    assert any(x.rule == "R4" for x in v)


def test_r4_forge_blocked_even_inside_crypto() -> None:
    """★ 密码层内部也不行：crypto/ 只有两个白名单文件能碰陷门。"""
    v = scan_text("m2, r2 = ch.forge((m, r), 5)", "crypto/phc/engine.py")
    assert any(x.rule == "R4" for x in v), "crypto/ 内部非白名单文件也必须受限"


def test_r4_whitelist_files_allowed() -> None:
    """两个定义/调用陷门的文件本身不受限，否则它们连自己的实现都写不了。"""
    for rel in ("crypto/primitives/chameleon.py", "crypto/hsm/soft.py"):
        v = scan_text("m2, r2 = self.forge((m, r), 5)", rel)
        assert v == [], f"{rel} 应在白名单内，实际：{[str(x) for x in v]}"


def test_r4_demos_not_exempt() -> None:
    """演示脚本会被抄走当样板 —— 它也没有资格绕过 R4。"""
    v = scan_text("ch.forge((m, r), 1)", "demos/demo.py")
    assert any(x.rule == "R4" for x in v)


def test_r4_ignores_prose() -> None:
    """文档里提到 forge 一词不应被误判成调用（AST 而非正则的意义）。"""
    v = scan_text("# forge 只能在白名单里调用", "services/note.py")
    assert v == []


def test_r4_cch_collide_r_confined_to_its_two_files() -> None:
    """tpaa_v1 的 AF 陷门：属性调用与裸名调用都抓；只有 cch.py / hsm/v1.py 能碰。"""
    for src in ("r2 = cch.collide_r(t, 1, x, r)", "r2 = collide_r(t, 1, x, r)"):
        for rel in ("services/evil.py", "crypto/tpaa_v1/engine.py", "demos/demo.py"):
            assert any(x.rule == "R4" for x in scan_text(src, rel)), f"{rel}: {src}"
        for rel in ("crypto/tpaa_v1/cch.py", "crypto/hsm/v1.py"):
            assert scan_text(src, rel) == [], rel
    # forge 的白名单不能拿来调 collide_r，反之亦然
    assert any(x.rule == "R4" for x in scan_text("collide_r(t,1,x,r)", "crypto/hsm/soft.py"))
    assert any(x.rule == "R4" for x in scan_text("ch.forge((m, r), 1)", "crypto/hsm/v1.py"))


def test_r2_blocks_tpaa_v1_internals() -> None:
    v = scan_text("from crypto.tpaa_v1.cch import af_value", "services/evil.py")
    assert any(x.rule == "R2" for x in v)


def test_scan_dir_clean_on_current_project() -> None:
    """当前项目业务代码（services/ 等）不应有任何越权。"""
    v = scan_dir(ROOT)
    assert v == [], f"项目当前应无越权，实际：{[str(x) for x in v]}"
