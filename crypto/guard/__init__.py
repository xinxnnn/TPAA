"""crypto/guard —— 越权静态检查卡口。

CI 用法：
    python -m crypto.guard            # 扫描项目根
    python -m crypto.guard /path/to/project
"""

from __future__ import annotations

from .checker import Violation, scan_dir, scan_text

__all__ = ["Violation", "scan_text", "scan_dir"]
