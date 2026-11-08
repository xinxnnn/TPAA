"""tpaa_v1 各服务共用的 HTTP 件：错误映射、时钟、请求号去重。

错误语义（与 did-service 同一套口径）：
    400  请求本身格式不对
    403  协议不成立 —— 签名不对、密文不是给你的、审批不够、归属人不符
    404  记录不存在
    409  重复：同一 requestId、同一张申请再签一次、同一会话再构建一次
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import crypto.sdk

log = logging.getLogger("tpaa.v1")


class NotFound(LookupError):
    pass


class Conflict(RuntimeError):
    pass


class Forbidden(PermissionError):
    pass


def install_errors(app: FastAPI) -> None:
    v1 = crypto.sdk.v1

    def _out(status: int, exc: Exception):
        return JSONResponse(status_code=status,
                            content={"code": status, "message": str(exc)})

    from .v1_auth import Unauthenticated

    @app.exception_handler(Unauthenticated)
    async def _ua(_: Request, exc: Unauthenticated):
        return JSONResponse(status_code=401, headers={"WWW-Authenticate": "Bearer"},
                            content={"code": 401, "message": str(exc)})

    @app.exception_handler(NotFound)
    async def _nf(_: Request, exc: NotFound):
        return _out(404, exc)

    @app.exception_handler(Conflict)
    async def _cf(_: Request, exc: Conflict):
        return _out(409, exc)

    for cls in (Forbidden, v1.ProtocolError, v1.PkeError, v1.SlotError, PermissionError):
        @app.exception_handler(cls)
        async def _fb(_: Request, exc: Exception):
            return _out(403, exc)

    @app.exception_handler(ValueError)
    async def _bad(_: Request, exc: ValueError):
        return _out(400, exc)

    @app.exception_handler(Exception)
    async def _boom(_: Request, exc: Exception):
        log.exception("未处理异常")
        return JSONResponse(status_code=500, content={"code": 500, "message": "内部错误"})


class SystemClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    def plus_hours(self, hours: int) -> str:
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


class FixedClock:
    def __init__(self, at: str = "2026-10-14T10:00:00") -> None:
        self.at = at

    def now(self) -> str:
        return self.at

    def plus_hours(self, hours: int) -> str:
        t = datetime.strptime(self.at, "%Y-%m-%dT%H:%M:%S") + timedelta(hours=hours)
        return t.strftime("%Y-%m-%dT%H:%M:%S")


def claim_request_id(store, scope: str, request_id: str, now: str) -> None:
    """requestId 去重（errata 限界 7）：同一 scope 下同一个号只认第一次。

    ★ 先登记、后处理。处理失败时号也作废 —— 让客户端换号重试，
      而不是让"失败后同号重放"成为一条能绕过去的路。
    """
    if not request_id:
        raise ValueError("缺少 requestId")
    key = f"{scope}:{request_id}"

    def _upd(d):
        seen = d.setdefault("requestIds", {})
        if key in seen:
            raise Conflict(f"requestId 已使用过：{request_id}")
        seen[key] = now
        return d

    store.update(_upd)


def hex_pk(pk) -> str:
    return crypto.sdk.v1.pk_hex(pk)


class LazyApp:
    """模块级 `app` 的惰性占位（理由同 agent-service）：import 不装配、不生成密钥。

    第一次被 ASGI 服务器调用时才执行 factory（通常是"从环境变量装配"），
    缺配置就在那一刻报错，而不是在 import 时、也不是在第一个请求里。
    """

    def __init__(self, factory) -> None:
        self._factory = factory
        self._inner = None

    def _get(self):
        if self._inner is None:
            self._inner = self._factory()
        return self._inner

    async def __call__(self, scope, receive, send):
        """ASGI3 三参签名 —— 必须显式写出来。

        ★ 以前是 `def __call__(self, *a, **kw)`。uvicorn 会按签名嗅探 ASGI 版本：
          看不到三个位置参数就当成 ASGI2，只传 scope 调用，于是真实启动必然 500
          （`FastAPI.__call__() missing 2 required positional arguments`）。
          测试用的是 `create_app(...)` 返回的 FastAPI 实例，绕过了这个包装，
          所以这条路一直没被测到。
        """
        await self._get()(scope, receive, send)

    def __getattr__(self, name):
        return getattr(self._get(), name)


def assert_single_worker(service: str) -> None:
    """拒绝多 worker / 多进程启动。

    ★ 为什么必须在代码里拦：`AuthIssuer` 的一次性 challenge 是**进程内**字典，
      JsonStore 的 load→fn→save 也只有本进程的 RLock。多开一个 worker，
      challenge 一次性消费和申请状态的 read-modify-write 立刻双双失效 ——
      这是安全属性，不能只在 README 里写一句。

    需要多 worker 时，先换成具备原子消费能力的共享存储，再放开这里。
    """
    import multiprocessing
    import os
    import sys

    def _refuse(why: str):
        raise RuntimeError(
            f"{service}：{why}。本轮各域服务只能单 worker 单进程启动"
            "（challenge 一次性消费与状态读改写没有跨进程原子性）")

    parent = getattr(multiprocessing, "parent_process", lambda: None)()
    if parent is not None:
        _refuse("检测到本进程是被派生的 worker 子进程")

    for var in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
        raw = (os.environ.get(var) or "").strip()
        if raw and raw != "1":
            _refuse(f"环境变量 {var}={raw}")

    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        value = None
        if arg.startswith("--workers=") or arg.startswith("-w="):
            value = arg.split("=", 1)[1]
        elif arg in {"--workers", "-w"}:
            value = argv[i + 1] if i + 1 < len(argv) else ""
        if value is not None and value.strip() != "1":
            _refuse(f"启动参数 {arg} {value}".strip())

    # Uvicorn multiprocessing spawn resets child process ancestry on Windows;
    # its own marker is the reliable in-child signal there.
    if os.environ.get("UVICORN_RELOAD") == "true" or os.environ.get("UVICORN_WORKER") == "true":
        _refuse("检测到 Uvicorn 子进程标记")


def env_required(name: str, default: str | None = None) -> str:
    """取环境变量。给了 default 就是"可省"，没给就是"缺了拒绝启动"。"""
    import os
    v = (os.environ.get(name) or "").strip()
    if not v:
        if default is not None:
            return default
        raise RuntimeError(f"缺少环境变量 {name}")
    return v


def hsm_from_seed(domain: str, env_var: str = "TPAA_V1_HSM_SEED", *, bindings=None):
    """从种子文件装配一把 V1 HSM。⚠️ 演练形态；生产换成 HSM/KMS 句柄，返回形态不变。

    文件格式：{"<domain 小写>": {"schnorr_sk": hex, "chameleon_sk": hex, "root": hex}}
    任何一项缺失都拒绝启动 —— 随机生成能起服务，但重启后既有凭证与槽位全部失效。
    """
    import json
    from pathlib import Path

    data = json.loads(Path(env_required(env_var)).read_text(encoding="utf-8"))
    try:
        return crypto.sdk.v1.hsm_from_seed(domain=domain, seed=data.get(domain.lower()) or {},
                                           bindings=bindings)
    except ValueError as exc:
        raise RuntimeError(f"{env_var}：{exc}") from exc


__all__ = ["NotFound", "Conflict", "Forbidden", "install_errors", "SystemClock",
           "FixedClock", "claim_request_id", "hex_pk", "LazyApp", "env_required", "hsm_from_seed",
           "assert_single_worker"]
