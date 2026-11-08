"""服务认证：挑战-签名登录 + 签发方签名的短期令牌。

    登录    客户端对 encode("AUTH/login", challenge, aud, signPk) 签名（钱包 / 审核员各用自己的密钥）
    令牌    base64url(claims) "." Sign_issuer(encode("AUTH/token", H(claims)))
            claims = {iss, sub, role, aud, iat, exp, jti}

★ 为什么不用口令：用户本来就有签名密钥（CR / AR 都靠它），审核员也该有自己的密钥 ——
  "谁判了通过"要落到一把具体的私钥上，而不是一个能被借用的口令。
★ aud 做域隔离：TP 签发的令牌拿到 AP 去用，aud 对不上即拒。
★ 签发方密钥（AUTH 域）与协议密钥分开：令牌签发方被攻破，也签不出 PHC。
"""

from __future__ import annotations

import secrets

from ..primitives.group import ser_point
from .encoding import encode
from .wire import ProtocolError, b64u, check_sig, json_digest, pk_from_hex, pk_hex, sign, unb64u

ROLES = ("user", "reviewer", "tp-operator", "supervisor", "ap-operator")


class AuthError(ProtocolError):
    """令牌或登录签名不成立。"""


def new_challenge() -> str:
    return secrets.token_hex(24)


def login_message(challenge: str, aud: str, sign_pk_hex: str) -> bytes:
    return encode("AUTH/login", challenge, aud, sign_pk_hex)


def sign_login(hsm, *, challenge: str, aud: str) -> str:
    """客户端（钱包 / 审核员）调用：对挑战签名。"""
    return sign(hsm, "AUTH/login", challenge, aud, pk_hex(hsm.pubkey()))


def check_login(*, sign_pk_hex: str, challenge: str, aud: str, sig: str) -> None:
    try:
        check_sig(pk_from_hex(sign_pk_hex), sig, "AUTH/login", challenge, aud, sign_pk_hex,
                  what="登录")
    except ProtocolError as exc:
        raise AuthError(str(exc)) from exc


def issue_token(issuer_hsm, *, sub: str, role: str, aud: str, iat: str, exp: str) -> str:
    if getattr(issuer_hsm, "domain", None) != "AUTH":
        raise PermissionError("令牌只能由 AUTH 域的签发方签")
    if role not in ROLES:
        raise ValueError(f"未知角色：{role}")
    claims = {"iss": pk_hex(issuer_hsm.pubkey()), "sub": sub, "role": role, "aud": aud,
              "iat": iat, "exp": exp, "jti": secrets.token_hex(8)}
    return b64u(claims) + "." + sign(issuer_hsm, "AUTH/token", json_digest(claims))


def verify_token(token: str, *, issuer_pk, aud: str, now: str) -> dict:
    try:
        body, sig = token.split(".")
        claims = unb64u(body)
    except (ValueError, TypeError) as exc:
        raise AuthError("令牌格式不对") from exc
    if claims.get("iss") != ser_point(issuer_pk).hex():
        raise AuthError("令牌不是本域签发方签的")
    try:
        check_sig(issuer_pk, sig, "AUTH/token", json_digest(claims), what="令牌")
    except ProtocolError as exc:
        raise AuthError(str(exc)) from exc
    if claims.get("aud") != aud:
        raise AuthError(f"令牌的 aud={claims.get('aud')!r}，本服务要求 {aud!r}")
    if not claims.get("exp") or claims["exp"] <= now:
        raise AuthError("令牌已过期")
    return claims


__all__ = ["ROLES", "AuthError", "new_challenge", "login_message", "sign_login",
           "check_login", "issue_token", "verify_token"]
