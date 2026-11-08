"""跨服务通用 DTO 与错误码（步骤 7 骨架）。

与 contracts/ 对齐：服务间交换的载荷以这些基类为最小约定，
具体字段在 contracts/<方>/ 下按 ARCHITECTURE 第十九章细化。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class ErrorCode(IntEnum):
    OK = 0
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    INTERNAL = 500
    # 协议相关
    CRYPTO_VERIFY_FAILED = 1400   # 凭证 / 派生链校验失败
    NOT_CONFIRMED = 1401          # 派生未经用户手动确认（红线：派生闸门）


@dataclass
class ApiResponse:
    code: int = 0
    message: str = "ok"
    data: Any = None


@dataclass
class Page:
    items: list = field(default_factory=list)
    total: int = 0
    page: int = 1
    size: int = 20


__all__ = ["ErrorCode", "ApiResponse", "Page"]
