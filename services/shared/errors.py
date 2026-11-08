"""统一异常（步骤 7 骨架）。"""

from __future__ import annotations

from .dto import ErrorCode


class TPAAError(Exception):
    """业务层统一异常；携带错误码，便于网关映射为 HTTP 状态。"""

    def __init__(self, code: ErrorCode, message: str, *, detail: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_response(self) -> dict:
        return {"code": int(self.code), "message": self.message, "detail": self.detail}


__all__ = ["TPAAError"]
