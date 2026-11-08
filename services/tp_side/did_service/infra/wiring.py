"""did-service 的装配。

★ 监管密钥的两个来源，区别非常大：

    `build_context(supervision_pub=...)`   生产：公钥由监管域注入，本服务只拿到封存能力
    `build_dev_context()`                  演练：本地生成一对，私钥**当场丢弃**

演练路径里私钥被丢掉，这一点值得说清楚：did-service 从设计上就不需要解密权，
就连"图省事把整把钥匙传进去"这条路也不给它留。演示时临时生成只是为了有个像样的 n，
生成完立刻只留公钥。
"""

from __future__ import annotations

import os

import crypto.sdk

from ..domain.services.context import ConfigError, DidContext
from .registry import DidRegistry


def build_context(*, db_path: str, supervision_pub, clock=None) -> DidContext:
    """生产装配。supervision_pub 必须是公钥形态（由监管域注入）。"""
    if supervision_pub is None:
        raise ConfigError("缺少监管公钥：did-service 需要它来封存 H(ID)")

    from .clock import SystemClock

    ctx = DidContext(
        registry=DidRegistry(db_path),
        supervision_pub=supervision_pub,
        clock=clock or SystemClock(),
        policy={"max_depth": int(os.environ.get("TPAA_MAX_TRACE_DEPTH") or 16)},
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, db_path: str, clock=None, bits: int = 2048) -> DidContext:
    """演练装配：生成一对监管密钥，随即只保留公钥。

    ⚠️ 只用于测试 / 本地演示。生产走 `build_context` + 监管域注入，
       因为演练密钥重启即换，上一轮封存的 CSCID 会全部解不开。
    """
    key = crypto.sdk.make_supervision_key(bits=bits)
    pub = key.public()
    del key                       # ★ 私钥当场丢弃：本服务用不到解密权
    return build_context(db_path=db_path, supervision_pub=pub, clock=clock)


__all__ = ["build_context", "build_dev_context", "ConfigError"]
