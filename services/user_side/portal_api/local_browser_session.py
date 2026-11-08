"""Process-local sessions for the explicitly enabled local browser test adapter."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from threading import RLock

from fastapi import HTTPException, Request


COOKIE_NAME = "tpaa_local_test_session"
SESSION_TTL_SECONDS = 20 * 60


@dataclass(frozen=True)
class Session:
    owner: str
    expires_at: float


class LocalBrowserSessions:
    def __init__(self, *, clock, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, Session] = {}
        self._lock = RLock()

    def create(self, owner: str) -> tuple[str, int]:
        now = self.clock()
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._purge(now)
            self._items[sid] = Session(owner=owner, expires_at=now + self.ttl_seconds)
        return sid, self.ttl_seconds

    def owner(self, sid: str | None) -> str | None:
        if not sid:
            return None
        now = self.clock()
        with self._lock:
            self._purge(now)
            session = self._items.get(sid)
            return session.owner if session else None

    def revoke(self, sid: str | None) -> None:
        if sid:
            with self._lock:
                self._items.pop(sid, None)

    def _purge(self, now: float) -> None:
        self._items = {sid: session for sid, session in self._items.items()
                       if session.expires_at > now}


def same_origin(request: Request, allowed_origin: str) -> None:
    origin = request.headers.get("origin")
    if not origin or origin.rstrip("/") != allowed_origin.rstrip("/"):
        raise HTTPException(status_code=403, detail="Origin mismatch")


def require_session(request: Request, sessions: LocalBrowserSessions) -> dict:
    owner = sessions.owner(request.cookies.get(COOKIE_NAME))
    if owner is None:
        raise HTTPException(status_code=401, detail="local test session missing or expired")
    return {"sub": owner, "role": "user", "profile": "test-adapter"}


__all__ = ["COOKIE_NAME", "SESSION_TTL_SECONDS", "LocalBrowserSessions", "same_origin",
           "require_session"]
