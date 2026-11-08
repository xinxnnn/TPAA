"""极简测试执行器（不依赖 pytest）。

    python run_tests.py              # 单元 + 对抗
    python run_tests.py --all        # 再加集成（需 fastapi/httpx）
    python run_tests.py --integration

为什么集成测试默认不跑：
    它要真起 HTTP、真落盘。在没装依赖的环境里它只能跳过，
    而"跳过"次数一多，失败就会被当成噪声 —— 不如让 `--all` 成为一个
    明确的选择：跑它，就代表这个环境是完整的。
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

TEST_DIRS = [ROOT / "tests" / "unit", ROOT / "tests" / "adversarial"]
INTEGRATION_DIRS = [ROOT / "tests" / "integration"]


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class Skipped(Exception):
    """测试自己声明"这个环境里跑不了"。

    刻意用异常而不是 `return`：
      `return` 无法与"跑完了但没断言"区分 —— 一个写漏了断言的测试
      会安静地变成通过。抛出来，运行器就必须显式记一笔"跳过"。
    """


def main() -> int:
    flags = set(sys.argv[1:])
    if flags & {"--all", "--integration"}:
        # Integration now includes pytest fixtures, parametrization and socket subprocesses.
        # This tiny runner cannot call those functions directly; hand the full selection
        # to pytest instead of reporting fixture TypeErrors as product test failures.
        dirs = TEST_DIRS + INTEGRATION_DIRS if "--all" in flags else INTEGRATION_DIRS
        return subprocess.call([sys.executable, "-m", "pytest", "-q", *(str(d) for d in dirs)])
    dirs = list(TEST_DIRS)

    passed = failed = skipped = 0
    for d in dirs:
        if not d.exists():
            continue
        print(f"\n{'=' * 70}\n  {d.relative_to(ROOT)}\n{'=' * 70}")
        for f in sorted(d.glob("test_*.py")):
            mod = load(f)
            for name in sorted(dir(mod)):
                if not name.startswith("test_"):
                    continue
                fn = getattr(mod, name)
                if not callable(fn):
                    continue
                try:
                    fn()
                    print(f"  [PASS] {f.stem}::{name}")
                    passed += 1
                except Skipped as exc:
                    print(f"  [SKIP] {f.stem}::{name} —— {exc}")
                    skipped += 1
                except Exception:  # noqa: BLE001
                    print(f"  [FAIL] {f.stem}::{name}")
                    traceback.print_exc()
                    failed += 1
    print(f"\n{'=' * 70}")
    print(f"  通过 {passed} 项，失败 {failed} 项，跳过 {skipped} 项")
    print("=" * 70)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
