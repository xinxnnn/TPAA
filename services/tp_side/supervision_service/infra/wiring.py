"""supervision-service 的装配。

★ 监管密钥只有一个入口：`build_context(key=...)`。
  没有"缺了就自己生成一把"的分支 —— 那等于每次重启换一把钥匙，
  上一轮封存的 CSCID 全部解不开。这种故障要等到第一次真正追溯时才暴露，
  而那时通常已经有人在等结果了。所以缺了就拒绝启动。
"""

from __future__ import annotations

import os

import crypto.sdk

from ..domain.services.context import ConfigError, SupervisionContext
from .adapters import IpfsByName, LocalAudit, LocalChannel, LocalDirectory
from .cases import CaseStore
from .clock import SystemClock


def build_context(*, db_path: str, directory, channel, storage, audit,
                  key, clock=None, tp_ch=None,
                  tau: int = 1, crf: int = 1) -> SupervisionContext:
    if key is None:
        raise ConfigError(
            "缺少监管密钥 —— 没有它就无法还原身份，追溯链在最后一公里断掉。"
            "请由监管域注入，不要在这里新生成：重启即换密钥会让历史 CSCID 全部作废。")

    ctx = SupervisionContext(
        cases=CaseStore(db_path),
        directory=directory, channel=channel, storage=storage, audit=audit,
        key=key, clock=clock or SystemClock(), tp_ch=tp_ch,
        policy={"tau": tau, "crf": crf},
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, db_path: str, did_ctx, coord_ctx, audit_ctx,
                      storage, ecid_key: bytes, key=None, clock=None,
                      tp_ch=None, bits: int = 2048) -> SupervisionContext:
    """本地演练装配。

    ⚠️ 不传 key 时会新生成一把 —— 只适用于演示与测试。
       生产必须由监管域注入同一把，否则历史 CSCID 解不开。
    """
    return build_context(
        db_path=db_path,
        directory=LocalDirectory(did_ctx),
        channel=LocalChannel(coord_ctx),
        storage=IpfsByName(storage=storage, ecid_key=ecid_key),
        audit=LocalAudit(audit_ctx=audit_ctx),
        key=key or crypto.sdk.make_supervision_key(bits=bits),
        clock=clock, tp_ch=tp_ch,
        tau=int(os.environ.get("TPAA_TAU") or 1),
        crf=int(os.environ.get("TPAA_CRF") or 1),
    )


__all__ = ["build_context", "build_dev_context", "ConfigError"]
