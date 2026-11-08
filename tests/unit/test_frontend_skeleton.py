"""步骤 8：frontend 四方骨架 + 前端边界卡口的自检。

前置：`python scripts/gen_frontend_skeleton.py`（生成骨架）。
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

FRONTEND = ROOT / "apps"

APPS = {
    "user-web": {"zone": "user", "prefix": "/api/user",
                 "pages": ["auth", "phc", "agent", "subagent",
                           "subagent/confirm", "vault", "lifecycle"]},
    "tp-web": {"zone": "tp", "prefix": "/api/tp",
               "pages": ["review", "phc", "did", "supervision"]},
    "ap-web": {"zone": "ap", "prefix": "/api/ap",
               "pages": ["modules", "primary-agents", "sub-agents", "lifecycle"]},
    "ops-web": {"zone": "ops", "prefix": "/api/ops",
                "pages": ["overview", "module-review", "stats", "permissions"]},
}

PENDING = "⏏ 骨架未生成，先跑 python scripts/gen_frontend_skeleton.py"


def _has(app: str, *parts: str) -> bool:
    return (FRONTEND / app / Path(*parts)).exists()


def test_four_apps_exist():
    """四方前端各自独立，外加中立的 shared/。"""
    for app in APPS:
        assert (FRONTEND / app).is_dir(), f"{app} 不存在 — {PENDING}"
    assert (FRONTEND / "shared").is_dir(), "shared/ 不存在"


def test_each_app_has_build_files():
    """每个应用可独立构建、独立端口部署（§10）。"""
    for app in APPS:
        for f in ("package.json", "tsconfig.json", "vite.config.ts",
                  "index.html", "src/main.tsx", "src/App.tsx",
                  "src/services/api-client.ts"):
            assert _has(app, f), f"{app} 缺少 {f} — {PENDING}"
        cfg = (FRONTEND / app / "vite.config.ts").read_text(encoding="utf-8")
        assert "changeOrigin" in cfg, f"{app} 未配置本区代理"


def test_pages_generated():
    """页面清单与 ARCHITECTURE §7 对应，尤其是派生确认页。"""
    for app, spec in APPS.items():
        for page in spec["pages"]:
            idx = FRONTEND / app / "src" / "pages" / page / "index.tsx"
            assert idx.exists(), f"{app} 缺少页面 {page} — {PENDING}"
    # V4 硬要求：派生必须用户手动确认
    confirm = FRONTEND / "user-web" / "src" / "pages" / "subagent" / "confirm" / "index.tsx"
    assert "手动确认" in confirm.read_text(encoding="utf-8")


def test_api_client_declares_zone():
    """每个 App 的 BASE_URL 必须落在本区前缀（§10 前端区）。"""
    for app, spec in APPS.items():
        src = (FRONTEND / app / "src" / "services" / "api-client.ts").read_text(encoding="utf-8")
        assert f"'{spec['prefix']}'" in src, f"{app} 的 BASE_URL 未声明为 {spec['prefix']}"
        assert f"'{spec['zone']}'" in src, f"{app} 未声明所属区"


def test_shared_has_four_packages():
    for pkg in ("ui", "auth", "api-client", "types"):
        base = FRONTEND / "shared" / pkg
        assert base.is_dir(), f"shared/{pkg} 不存在"
        files = [p.name for p in base.iterdir() if p.suffix in (".ts", ".tsx")]
        assert files, f"shared/{pkg} 为空"


# ---------------- boundary guard ----------------

def _make(tmp: Path, app: str, rel: str, content: str) -> Path:
    p = tmp / app / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_boundary_clean_on_real_frontend():
    """当前 frontend/ 必须零违规。"""
    from check_frontend_boundary import check

    violations = check(FRONTEND)
    assert violations == [], "frontend 存在边界违规：\n" + "\n".join(str(v) for v in violations)


def test_boundary_catches_crypto_import():
    """F1：前端引入加密库必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "user-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/user'\n")
        _make(tmp, "user-web", "src/x.ts", "import CryptoJS from 'crypto-js'\n")
        vs = check(tmp)
        assert any(v.rule == "F1" for v in vs), "F1 未能拦截加密库引入"


def test_boundary_catches_subtle_and_secret():
    """F1：SubtleCrypto 调用与密钥标识符必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "user-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/user'\n")
        _make(tmp, "user-web", "src/cryptoish.ts",
              "const k = await crypto.subtle.generateKey({})\nconst privateKey = k\n")
        vs = check(tmp)
        assert sum(1 for v in vs if v.rule == "F1") >= 2, "F1 未同时命中 subtle 与密钥标识符"


def test_boundary_catches_cross_zone():
    """F2：tp-web 里出现 /api/ap 必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "tp-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/tp'\n")
        _make(tmp, "tp-web", "src/pages/review/index.tsx",
              "export const url = '/api/ap/agent-service/list'\n")
        vs = check(tmp)
        assert any(v.rule == "F2" for v in vs), "F2 未能拦截跨域直连"


def test_boundary_catches_localstorage_persist():
    """F3：会话写 localStorage 必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "user-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/user'\n")
        _make(tmp, "user-web", "src/store/session.ts",
              "localStorage.setItem('tpaa.session', JSON.stringify(s))\n")
        vs = check(tmp)
        assert any(v.rule == "F3" for v in vs), "F3 未能拦截会话落盘"


def test_boundary_catches_shared_leak():
    """F4：shared 里出现 BASE_URL / 区前缀必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "shared", "api-client/index.ts",
              "export const BASE_URL = '/api/user'\n")
        vs = check(tmp)
        assert any(v.rule == "F4" for v in vs), "F4 未能拦截 shared 泄漏区划属"


def test_boundary_requires_api_client():
    """F5：缺少 BASE_URL 声明的服务出口必须被拦下。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "ap-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/user'\n")
        vs = check(tmp)
        assert any(v.rule == "F5" for v in vs), "F5 未能识别 BASE_URL 与所属区不符"


def test_comment_not_false_positive():
    """注释里的说明性文字不得被误判（注释先剥离）。"""
    from check_frontend_boundary import check

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _make(tmp, "tp-web", "src/services/api-client.ts",
              "export const BASE_URL = '/api/tp'\n")
        _make(tmp, "tp-web", "src/note.ts",
              "// 禁止 import crypto-js，前端不做加密；也不得写 /api/ap\n")
        assert check(tmp) == [], "注释被误判为违规"
