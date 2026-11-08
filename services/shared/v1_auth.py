"""v1 服务的认证接线：登录端点 + 令牌校验依赖。

    POST /v1/auth/challenge   取一次性挑战（5 分钟有效、用过即废）
    POST /v1/auth/login       {challenge, signPk, sig} → 令牌
                              signPk 在人员名录里 → 按名录给角色（审核员等）
                              不在名录里         → 角色 user，sub = 该公钥的归属人指纹

各服务在端点上声明 `Depends(verifier.require("reviewer"))`，拿到的是已验过的 claims。

⚠️ 人员名录（signPk → {id, role}）由部署注入。名录里"一人一把钥匙"是组织层面的规矩：
   同一个人领两把钥匙，"双人审核"一样会被一个人完成 —— 这一点代码管不到。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock

from fastapi import Body, Depends, FastAPI, Header

import crypto.sdk

from .v1_http import Forbidden

v1 = crypto.sdk.v1
_FMT = "%Y-%m-%dT%H:%M:%S"
CHALLENGE_TTL_MIN = 5
TOKEN_TTL_MIN = 30


def _plus_min(now: str, minutes: int) -> str:
    return (datetime.strptime(now, _FMT) + timedelta(minutes=minutes)).strftime(_FMT)


class Unauthenticated(PermissionError):
    """没带令牌 / 令牌无效（401）。与"带了令牌但角色不够"（403）分开。"""


@dataclass
class AuthIssuer:
    """一个域（TP / AP）的令牌签发方。"""

    issuer_hsm: object
    aud: str
    clock: object
    staff: dict = field(default_factory=dict)        # signPkHex → {"id", "role"}
    _challenges: dict = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def challenge(self) -> dict:
        with self._lock:
            now = self.clock.now()
            self._challenges = {c: v for c, v in self._challenges.items() if v["exp"] > now}
            c = v1.auth.new_challenge()
            self._challenges[c] = {"exp": _plus_min(now, CHALLENGE_TTL_MIN)}
            return {"challenge": c, "aud": self.aud, "expires": self._challenges[c]["exp"]}

    def login(self, *, challenge: str, sign_pk: str, sig: str) -> dict:
        with self._lock:
            entry = self._challenges.pop(challenge, None)
        now = self.clock.now()
        if entry is None or entry["exp"] <= now:
            raise Unauthenticated("挑战不存在、已用过或已过期")
        try:
            v1.auth.check_login(sign_pk_hex=sign_pk, challenge=challenge, aud=self.aud, sig=sig)
        except v1.auth.AuthError as exc:
            raise Unauthenticated(str(exc)) from exc
        return self.token_for(sign_pk)

    def token_for(self, sign_pk: str) -> dict:
        """按公钥签发令牌（名录里的人员按名录给角色，其余为 user）。调用方负责先认证。"""
        now = self.clock.now()
        member = self.staff.get(sign_pk)
        if member is not None:
            sub, role = member["id"], member["role"]
        else:
            sub, role = v1.owner_of(v1.pk_from_hex(sign_pk)), "user"
        exp = _plus_min(now, TOKEN_TTL_MIN)
        tok = v1.auth.issue_token(self.issuer_hsm, sub=sub, role=role, aud=self.aud,
                                  iat=now, exp=exp)
        return {"token": tok, "sub": sub, "role": role, "expires": exp}

    def verifier(self) -> "AuthVerifier":
        return AuthVerifier(issuer_pk=self.issuer_hsm.pubkey(), aud=self.aud, clock=self.clock)


@dataclass
class AuthVerifier:
    issuer_pk: object
    aud: str
    clock: object

    def check(self, authorization: str | None) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise Unauthenticated("缺少 Authorization: Bearer <token>")
        try:
            return v1.auth.verify_token(authorization[7:], issuer_pk=self.issuer_pk,
                                        aud=self.aud, now=self.clock.now())
        except v1.auth.AuthError as exc:
            raise Unauthenticated(str(exc)) from exc

    def require(self, *roles: str):
        def _dep(authorization: str | None = Header(default=None)) -> dict:
            claims = self.check(authorization)
            if roles and claims["role"] not in roles:
                raise Forbidden(f"需要角色 {'/'.join(roles)}，当前为 {claims['role']}")
            return claims
        return Depends(_dep)


def install_auth_routes(app: FastAPI, issuer: AuthIssuer) -> None:
    @app.post("/v1/auth/challenge")
    def challenge():
        return issuer.challenge()

    @app.post("/v1/auth/login")
    def login(challenge: str = Body(...), signPk: str = Body(...), sig: str = Body(...)):
        return issuer.login(challenge=challenge, sign_pk=signPk, sig=sig)


def require_owner(claims: dict, owner: str, *, operator_roles: tuple[str, ...] = ()) -> None:
    """资源归属检查：本人，或者具备运营角色。"""
    if claims["role"] in operator_roles:
        return
    if claims["role"] != "user" or claims["sub"] != owner:
        raise Forbidden("只能操作属于自己的申请 / 会话")


__all__ = ["AuthIssuer", "AuthVerifier", "Unauthenticated", "install_auth_routes",
           "require_owner", "TOKEN_TTL_MIN"]
