"""依赖装配：把端口实现、localstore、HSM 装进一个 `AgentServiceContext`。

为什么装配单独成文件、不写在 app.py 里：
    app.py 负责"请求怎么进来、错误怎么出去"，装配负责"这些东西从哪来"。
    混在一起时，任何一次测试想换掉一个端口，都得先把 HTTP 层拉起来 ——
    测试成本一高，就会有人选择"不测"。

为什么密钥只能从**环境变量**取、且不接受默认值：
    索引密钥与 ECID 密钥一旦用了默认值，整个部署里所有实例就共用一把，
    而这种错误不会在运行时报出来，只在出事那天才被发现。
    所以缺了就拒绝启动 —— 见 `InfraConfig.from_env`。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import crypto.sdk

from localstore import (
    AgentStore,
    IdentityIndex,
    Layout,
    ModuleRepo,
    OwnerIndex,
)

from ..domain.services.context import AgentServiceContext, ConfigError
from .capability import LocalCapabilityAdapter, LocalTpAuthority
from .clock import FixedClock, SystemClock
from .content import LocalIpfsAdapter


@dataclass(frozen=True)
class InfraConfig:
    """部署参数。全部来自环境变量，没有"忘记配也能跑"的默认值。"""

    store_root: str
    index_key_hex: str
    ecid_key_hex: str
    did_prefix: str = "did:tpaa"
    max_sub_ttl_hours: int = 720
    tau: int = 1
    crf: int = 1

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "InfraConfig":
        e = os.environ if env is None else env

        def need(name: str) -> str:
            v = (e.get(name) or "").strip()
            if not v:
                raise ConfigError(
                    f"缺少环境变量 {name}。"
                    "索引密钥与 ECID 密钥必须由部署注入，不接受默认值 —— "
                    "默认值会让所有实例共用一把密钥，而且运行时不会报错。")
            return v

        def hex_bytes(name: str, min_len: int) -> str:
            v = need(name)
            try:
                raw = bytes.fromhex(v)
            except ValueError as exc:
                raise ConfigError(f"{name} 必须是十六进制字符串") from exc
            if len(raw) < min_len:
                raise ConfigError(f"{name} 至少 {min_len} 字节，实际 {len(raw)}")
            return v

        return cls(
            store_root=need("TPAA_STORE_ROOT"),
            index_key_hex=hex_bytes("TPAA_INDEX_KEY", 32),
            ecid_key_hex=hex_bytes("TPAA_ECID_KEY", 32),
            did_prefix=(e.get("TPAA_DID_PREFIX") or "did:tpaa").strip(),
            max_sub_ttl_hours=int(e.get("TPAA_MAX_SUB_TTL_HOURS") or 720),
            tau=int(e.get("TPAA_TAU") or 1),
            crf=int(e.get("TPAA_CRF") or 1),
        )


def load_hsm_seed(env: dict[str, str] | None = None):
    """从 `TPAA_HSM_SEED` 指向的种子文件装配 TP / AP 两把 HSM。

    格式与 `scripts/verify_localstore.py --hsms` 相同：
        {"tp": {"schnorr_sk": "<hex>", "chameleon_sk": "<hex>"}, "ap": {...}}

    ★ 缺文件、缺字段一律拒绝启动，不退回随机密钥：
      随机密钥能起服务，但库里已有的凭证从此全部验不过，而且不会报"配置错了"。
    ⚠️ 种子文件是演练形态。生产把本函数换成从 HSM/KMS 取句柄，返回形态不变。
    """
    import json

    e = os.environ if env is None else env
    path = (e.get("TPAA_HSM_SEED") or "").strip()
    if not path:
        raise ConfigError(
            "缺少环境变量 TPAA_HSM_SEED。HSM 密钥必须由部署注入，"
            "不再每次启动随机生成（否则重启后既有 PHC 全部验签失败）")
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"HSM 种子文件不可读：{path}") from exc

    def mk(domain: str, key: str):
        node = data.get(key) or {}
        try:
            return crypto.sdk.make_demo_hsm(
                domain=domain,
                schnorr_sk=int(node["schnorr_sk"], 16),
                chameleon_sk=int(node["chameleon_sk"], 16),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"HSM 种子缺少或损坏 {key}.schnorr_sk / {key}.chameleon_sk") from exc

    return mk("TP", "tp"), mk("AP", "ap")


def build_context(*, config: InfraConfig, tp_hsm, ap_hsm,
                  storage, clock=None) -> AgentServiceContext:
    """装配并做一次启动自检。自检不过就抛，不允许带病启动。"""
    layout = Layout(Path(config.store_root))
    ipfs = LocalIpfsAdapter(storage=storage)
    authority = LocalTpAuthority(
        tp_hsm=tp_hsm,
        # ★ 跨域只交公钥：TP 替身拿不到 AP 的陷门
        ap_pk=ap_hsm.pubkey(), ap_ch=ap_hsm.public_chameleon(),
        ecid_key=bytes.fromhex(config.ecid_key_hex),
        did_prefix=config.did_prefix,
        # TP 侧状态与 AP 的 localstore 分目录：演练时同盘，部署时本就在 TP 机房
        state_dir=layout.root / "_tp_state",
    )

    ctx = AgentServiceContext(
        layout=layout,
        modules=ModuleRepo(layout),
        agents=AgentStore(layout),
        identity_index=IdentityIndex(layout),
        owner_index=OwnerIndex(layout),
        ap_hsm=ap_hsm,
        index_key=bytes.fromhex(config.index_key_hex),
        capability=LocalCapabilityAdapter(authority, ap_hsm=ap_hsm),
        content=ipfs,
        clock=clock or SystemClock(),
        policy={
            "max_sub_ttl_hours": config.max_sub_ttl_hours,
            "tau": config.tau,
            "crf": config.crf,
        },
    )
    ctx.ensure_healthy()
    return ctx


def build_dev_context(*, store_root: str, storage, clock=None,
                      tp_hsm=None, ap_hsm=None) -> AgentServiceContext:
    """本地演练装配：自动生成两把 HSM 与两把密钥。

    ⚠️ 只用于测试 / 本地演示。生产走 `build_context` + 真实注入，
       因为"自动生成密钥"在生产上意味着重启即换密钥 —— 索引立刻解不开。
    """
    return build_context(
        config=InfraConfig(
            store_root=store_root,
            index_key_hex=os.urandom(32).hex(),
            ecid_key_hex=os.urandom(32).hex(),
        ),
        tp_hsm=tp_hsm or crypto.sdk.make_demo_hsm(domain="TP"),
        ap_hsm=ap_hsm or crypto.sdk.make_demo_hsm(domain="AP"),
        storage=storage,
        clock=clock,
    )


__all__ = ["InfraConfig", "build_context", "build_dev_context", "load_hsm_seed", "FixedClock"]
