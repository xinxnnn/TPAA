"""CI 卡口入口：python -m crypto.guard [root]

发现越权即以退出码 1 失败，可接进 CI 流水线。
"""

from __future__ import annotations

import sys
from pathlib import Path

from .checker import scan_dir


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
    violations = scan_dir(root)
    if violations:
        print(f"[guard] 发现 {len(violations)} 处越权调用密码学：")
        for v in violations:
            print(f"  {v}")
        return 1
    print("[guard] 通过：未发现越权调用密码学")
    return 0


if __name__ == "__main__":
    sys.exit(main())
