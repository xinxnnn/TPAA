"""测试脚手架：两方 TP / AP，以及整条追溯链的装配。

★ `Parties` 刻意只产出**句柄**，不产出密钥：

    hsm        本域私有，能签名、能求碰撞（陷门在里面）
    public     跨域给出去的那一份，只能算值、不能改内容

上层代码能拿到的东西，测试里也一样只能拿到这些东西 ——
否则测试自己就成了绕过红线的后门。

★ `TraceChain` 放在这里而不是某个测试文件里，是因为它现在被两处用：
  领域层的全链测试（不起 HTTP，验规则）和 HTTP 层的集成测试（起真实端点，验接缝）。
  两套夹具各写一遍的话，早晚会有一边悄悄少接一个服务 ——
  而那种"少接"，表现出来是"某个功能忽然不生效"，排查成本极高。
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.hsm import SoftHSM  # noqa: E402


def identity_hash(seed: bytes = b"110101199003071234") -> int:
    """把自然人身份压成一个群元素意义上的整数 H(ID)。"""
    return int.from_bytes(hashlib.sha256(seed).digest(), "big")


class Parties:
    """TP 与 AP 两方，各自持有独立的 HSM 句柄。"""

    def __init__(self, *, tp: SoftHSM | None = None, ap: SoftHSM | None = None) -> None:
        self.tp_hsm = tp or SoftHSM(domain="TP")
        self.ap_hsm = ap or SoftHSM(domain="AP")

        # 跨域交换的那一份：只有公钥
        self.tp_pub = self.tp_hsm.public_chameleon()
        self.ap_pub = self.ap_hsm.public_chameleon()

        self.tp_pk = self.tp_hsm.pubkey()
        self.ap_pk = self.ap_hsm.pubkey()

    def verify_kwargs(self, *, identity_hash: int, tau: int, crf: int) -> dict:
        """verify_phc 的公开参数 —— 校验是公开动作，只用公钥材料。"""
        return dict(
            tp_pk=self.tp_pk, ap_pk=self.ap_pk,
            tp_ch=self.tp_pub, ap_ch=self.ap_pub,
            identity_hash=identity_hash, tau=tau, crf=crf,
        )


# ---------------------------------------------------------------------------
# 服务加载器
# ---------------------------------------------------------------------------

_LOADED: dict[str, object] = {}

_SERVICES = {
    "agent-service": "services.ap_side.agent_service",
    "lifecycle-service": "services.ap_side.lifecycle_service",
    "did-service": "services.tp_side.did_service",
    "supervision-service": "services.tp_side.supervision_service",
    "coordination": "services.cross_domain.coordination",
    "policy-service": "services.cross_domain.policy_service",
    "audit-service": "services.cross_domain.audit_service",
    "gateway": "services.ap_side.gateway",
}


def load_service(service: str, module: str):
    """加载某个服务里的一个模块，如 load_service("did-service", "domain.usecases")。

    ★ 关于带连字符的目录名：
      `services.ap_side.agent_service` is imported by `importlib` using its package path.
      importlib 按名字找目录，不要求它是标识符（只有 `import a.b` 这种语法形式受限）。
      所以这里直接走真实 import，模块内部的相对导入照旧生效，
      拿到的是**唯一一份**模块对象，不会因为"按路径再加载一次"而出现
      两个互不相同的类（那种情况下 isinstance 会莫名其妙地失败）。
    """
    if service not in _SERVICES:
        raise KeyError(f"未知服务 {service!r}；已知：{sorted(_SERVICES)}")
    key = f"{_SERVICES[service]}.{module}"
    if key not in _LOADED:
        import importlib

        _LOADED[key] = importlib.import_module(key)
    return _LOADED[key]


def load_agent_service(module: str):
    """加载 agent-service 里的一个模块（保留旧名，避免改动既有测试）。"""
    return load_service("agent-service", module)


def load_agent_service_app():
    """拿到 agent-service 的 app 模块（含 create_app）。"""
    return load_agent_service("app")


# ---------------------------------------------------------------------------
# 整条追溯链：六个服务装进同一个临时目录
# ---------------------------------------------------------------------------

CHAIN_MODULES = {"engine.py": b"def run(text):\n    return text[:80]\n"}


class TraceChain:
    """把六个服务装配到同一个临时目录里。

    ★ 全局只生成一次监管密钥。
      这不是为了省时间 —— 而是因为"用两把不同的钥匙"是本链路最真实的失败模式：
      did-service 用 A 封存、supervision 用 B 还原，报出来的会是
      "解密得到一串乱码"，看起来像算法坏了，实际是装配错了。
    """

    def __init__(self) -> None:
        import crypto.sdk
        from services.ipfs.storage_service.app import StorageService


        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        self.storage = StorageService()

        # ---- 时钟：全链共用一个，时间才能对齐 ----
        self.clock = load_service("agent-service", "infra.clock").FixedClock()
        self.t_audit = load_service("audit-service", "infra.clock").FixedClock()
        self.t_did = load_service("did-service", "infra.clock").FixedClock()
        self.t_coord = load_service("coordination", "infra.clock").FixedClock()

        # ---- 密钥：监管一对、索引/ECID 各一 ----
        self.sup_key = crypto.sdk.make_supervision_key(bits=1024 * 2)
        self.ecid_key = os.urandom(32)

        # ---- 审计 ----
        self.audit_ctx = load_service("audit-service", "infra.wiring").build_dev_context(
            db_path=str(root / "audit.json"), clock=self.t_audit)

        # ---- 协调 ----
        self.coord_ctx = load_service("coordination", "infra.wiring").build_dev_context(
            db_path=str(root / "tickets.json"), clock=self.t_coord)

        # ---- did ----
        self.did_ctx = load_service("did-service", "infra.wiring").build_context(
            db_path=str(root / "did.json"),
            supervision_pub=self.sup_key.public(),
            clock=self.t_did)

        # ---- agent（AP）----
        infra = load_service("agent-service", "infra.wiring")
        self.tp_hsm = crypto.sdk.make_demo_hsm(domain="TP")
        self.ap_hsm = crypto.sdk.make_demo_hsm(domain="AP")
        self.agent_ctx = infra.build_context(
            config=infra.InfraConfig(
                store_root=str(root / "store"),
                index_key_hex=os.urandom(32).hex(),
                ecid_key_hex=self.ecid_key.hex(),
            ),
            tp_hsm=self.tp_hsm,
            ap_hsm=self.ap_hsm,
            storage=self.storage,
            clock=self.clock,
        )
        for mid in ("summarize", "translate"):
            self.agent_ctx.modules.publish(mid, "1.0.0", CHAIN_MODULES, description=mid)

        # ---- lifecycle（AP）----
        self.life_ctx = load_service("lifecycle-service", "infra.wiring").build_dev_context(
            store_root=str(root / "store"), agent_ctx=self.agent_ctx, clock=self.clock)

        # ---- supervision（TP）----
        # tp_ch 取 TP HSM 的**公开形态**：AF 复算只需要公钥，不需要陷门
        tp_pub = crypto.sdk.public_from_cpk(self.tp_hsm.chameleon_cpk())

        self.sup_ctx = load_service("supervision-service", "infra.wiring").build_dev_context(
            db_path=str(root / "cases.json"),
            did_ctx=self.did_ctx, coord_ctx=self.coord_ctx, audit_ctx=self.audit_ctx,
            storage=self.storage, ecid_key=self.ecid_key,
            key=self.sup_key, clock=self.clock, tp_ch=tp_pub, bits=2048)

        # ---- policy（跨域）----
        self.policy_ctx = load_service("policy-service", "infra.wiring").build_dev_context(
            db_path=str(root / "orders.json"),
            did_ctx=self.did_ctx, lifecycle_ctx=self.life_ctx,
            audit_ctx=self.audit_ctx, clock=self.clock)

        # ---- gateway（AP 的对外出入口）----
        # 进程内形态：通道是函数调用。分区形态见 build_http_context。
        self.gw_ctx = load_service("gateway", "infra.wiring").build_dev_context(
            coord_ctx=self.coord_ctx, lifecycle_ctx=self.life_ctx,
            audit_ctx=self.audit_ctx, clock=self.t_coord)

        self.hid = identity_hash(b"110101199003071234")

    # ---- 便捷 ----
    def agent(self, name: str):
        return load_service("agent-service", f"domain.usecases.{name}")

    def close(self) -> None:
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # 前半程：申领 → 派生 → 登记 → G2 信封
    # ------------------------------------------------------------------

    def issue_primary(self) -> tuple[str, dict]:
        uc = load_service("agent-service", "domain.usecases")
        ent = load_service("agent-service", "domain.entities")
        sel = ent.Selection(choices=(ent.ModuleChoice("summarize", "1.0.0"),))
        out = uc.IssueAgentUseCase(self.agent_ctx).execute(uc.IssueCommand(
            identity_hash=self.hid, tau=1, crf=1, selection=sel, ttl_days=0))
        return out.did, out.phc_json

    def derive_child(self, parent_did: str) -> tuple[str, dict]:
        uc = load_service("agent-service", "domain.usecases")
        ent = load_service("agent-service", "domain.entities")
        sel = ent.Selection(choices=(ent.ModuleChoice("translate", "1.0.0"),))

        ticket = uc.DeriveSubAgentUseCase(self.agent_ctx).prepare(
            parent_did=parent_did, selection=sel, ttl_hours=720)
        tok = uc.DeriveSubAgentUseCase(self.agent_ctx).confirm(
            token=f"cfm-{ticket.ticket_id}",
            ticket=uc.ConfirmationTicket(
                ticket_id=ticket.ticket_id, parent_did=ticket.parent_did,
                selection_digest=ticket.selection_digest,
                ttl_hours=ticket.ttl_hours, created_at=ticket.created_at))
        out = uc.DeriveSubAgentUseCase(self.agent_ctx).execute(ent.ChildRequest(
            parent_did=parent_did, selection=sel, ttl_hours=720,
            confirmation=uc.DeriveSubAgentUseCase(self.agent_ctx).load_ticket(tok.token)))
        return out.did, out.phc_json

    def g2_envelope(self, bi_payload: bytes = b'{"name":"zhangsan","idNo":"1101..."}') -> str:
        """模拟 G2：把身份材料加密放进第五方，返回 ECID。"""
        import crypto.sdk

        cid = self.storage.put(bi_payload, requester="phc-service")
        self.storage.pin(cid, requester="phc-service")
        return crypto.sdk.protect_cid(cid, self.ecid_key)

    def register(self, did: str, *, parent: str = "", ecid: str = "") -> None:
        uc = load_service("did-service", "domain.usecases")
        uc.RegisterDidUseCase(self.did_ctx).execute(uc.RegisterCommand(
            did=did, identity_hash=self.hid, parent_did=parent, ecid_ref=ecid,
            confirmed_by_user=bool(parent)))

    def seed(self) -> tuple[str, str]:
        """建好主 + 子两只，返回 (主 DID, 子 DID)。

        两只挂同一个 ECID：它们属于同一个人，身份材料也只有一份。
        """
        root_did, _ = self.issue_primary()
        ecid = self.g2_envelope()
        self.register(root_did, ecid=ecid)
        sub_did, _ = self.derive_child(root_did)
        self.register(sub_did, parent=root_did, ecid=ecid)
        return root_did, sub_did


class chain_env:
    """with 语法糖：退出时清掉临时目录。"""

    def __init__(self) -> None:
        self.c: TraceChain | None = None

    def __enter__(self) -> TraceChain:
        self.c = TraceChain()
        return self.c

    def __exit__(self, *exc) -> None:
        if self.c is not None:
            self.c.close()

