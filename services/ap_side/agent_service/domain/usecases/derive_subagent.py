"""用例 2：派生子智能体（ARCHITECTURE §9.3）。

这一步的唯一重点是**闸门**，其余都是从主智能体流程复用的同一套动作。

    用户端 ──选能力/有效期──▶ 生成确认任务（拿到 selection_digest）
    用户端 ──手动确认──────▶ 换一张一次性的确认令牌（绑定该 digest）
    用例 ──①②③──────────▶ 校验令牌 → 派生 → 封唯一 DID

三道判断，缺一不可（对应 entities.ChildRequest.guard + 本文件）：

    ① 有没有令牌 —— 没有就直接拒，**不进入任何密钥动作**
    ② 令牌是不是这次的 —— digest 对不上说明确认之后方案被改过，拒
    ③ 令牌是不是用过了 —— 一次性，用过即废

为什么闸门放在「算 CMI 之前」而不是「封 DID 之前」：
    闸门的意思是"用户没点头之前，平台不能替他把这件事想下去"。
    如果等到快结尾才拦，前面已经用了他的身份哈希、读了模块、算出了配置承诺 ——
    这已经不是"没发生"，只是"结果没交付"。所以闸门必须挡在第一个密钥动作之前。

子体与主智能体**同流程、同校验**：
    唯一 DID、自己的 PHC（AF 里封 parent_did）、自己的 localstore 实例。
    不共用父体的 DID、不共用父体的 APCH —— 否则吊销一个等于吊销两个。
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass

import crypto.sdk

from localstore import (
    AgentMeta,
    AgentState,
    AgentType,
    CmiRecord as StoreCmiRecord,
    Selection as StoreSelection,
)

from ..entities import (
    ChildRequest,
    NotConfirmed,
    Selection,
    digest_selection,
)
from ..ports import (
    IssueRequest,
    PublicKeyMaterial,
    SealDidRequest,
    WriteCmiRequest,
)
from ..services.build import assemble
from ..services.cmi import compute_cmi
from ..services.context import AgentServiceContext
from .issue_agent import IssueRejected


# 待确认任务与令牌台账都是"读 → 改 → 写"，并发两次请求会都读到旧值、都通过。
# FastAPI 的同步端点跑在线程池里，所以至少要有进程内互斥。
# ⚠️ 多进程部署（多个 uvicorn worker）时这把锁不够，台账须换成带事务的存储。
_LEDGER_LOCK = threading.Lock()


@dataclass(frozen=True)
class ConfirmationTicket:
    """待确认的派生方案。用户确认时，它被换成一张一次性令牌。"""

    ticket_id: str
    parent_did: str
    selection_digest: str
    ttl_hours: int
    created_at: str


@dataclass(frozen=True)
class DeriveResult:
    did: str
    phc_json: dict
    cmi: str
    parent_did: str
    expires_at: str
    build_digest: str


class DeriveSubAgentUseCase:
    def __init__(self, ctx: AgentServiceContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------
    # 第一步：生成确认任务（此步**不做任何密钥动作**）
    # ------------------------------------------------------------------
    def prepare(self, *, parent_did: str, selection: Selection,
                ttl_hours: int) -> ConfirmationTicket:
        if not selection.choices:
            raise IssueRejected("至少选择一个模块")
        if not self.ctx.agents.exists(parent_did):
            raise IssueRejected(f"父体不存在：{parent_did}")
        parent = self.ctx.agents.load_meta(parent_did)
        if parent.agent_type is not AgentType.PRIMARY:
            # 子体不能再派生 —— 否则追溯链会变成树，级联吊销的"根"也就不唯一了
            raise IssueRejected("只有主智能体可以派生子体")

        cap = int(self.ctx.policy.get("max_sub_ttl_hours", 720))
        if ttl_hours <= 0 or ttl_hours > cap:
            raise IssueRejected(f"子体有效期必须在 1–{cap} 小时之间（实际 {ttl_hours}）")

        self._assert_selection_available(selection)

        # ★ ticket_id 必须随机、且登记在案：
        #   原先是 `tkt-<digest 前缀>`，谁都能算出来，confirm 也不查它是否 prepare 过，
        #   于是"先 prepare 再 confirm"这条时序只是约定，任何人一步就能换到令牌。
        ticket = ConfirmationTicket(
            ticket_id=f"tkt-{secrets.token_hex(16)}",
            parent_did=parent_did,
            selection_digest=digest_selection(selection),
            ttl_hours=ttl_hours,
            created_at=self.ctx.clock.now(),
        )
        with _LEDGER_LOCK:
            pending = self._load_json(self._pending_path())
            pending[ticket.ticket_id] = {
                "parentDid": ticket.parent_did,
                "selectionDigest": ticket.selection_digest,
                "ttlHours": ticket.ttl_hours,
                "createdAt": ticket.created_at,
                "confirmedAt": "",
            }
            self._save_json(self._pending_path(), pending)
        return ticket

    # ------------------------------------------------------------------
    # 第二步：用户手动确认之后才真正派生
    # ------------------------------------------------------------------
    def execute(self, req: ChildRequest) -> DeriveResult:
        # ---- 闸门：三道判断一口气做完，做完才允许碰密钥 ----
        req.guard()
        # ★ 令牌绑定父体：为父体 A 确认的令牌不能拿去在父体 B 名下派生
        if self._token_parent(req.confirmation.token) != req.parent_did:
            raise NotConfirmed("确认令牌不是为这个父体签发的")

        parent = self.ctx.agents.load_meta(req.parent_did)
        if parent.state is not AgentState.ACTIVE:
            raise IssueRejected(f"父体状态为 {parent.state.value}，不能派生")

        # 父 PHC 必须存在且能验过 —— 父体的凭证都不可信，就别谈从它派生
        parent_phc = self._load_parent_phc(req.parent_did)
        if not parent_phc:
            raise IssueRejected(f"父体 PHC 缺失：{req.parent_did}")
        hid_hex = self._hid_of(req.parent_did)
        tau = int(self.ctx.policy.get("tau", 1))
        crf = int(self.ctx.policy.get("crf", 1))
        check = self.ctx.capability.verify_phc(
            parent_phc, identity_hash=int(hid_hex, 16), tau=tau, crf=crf)
        if not check.ok:
            raise IssueRejected("父体 PHC 校验未通过：" + "；".join(check.errors))

        resolved = self._resolve(req.selection)
        cmi = compute_cmi(resolved)

        material = self._public_material()

        # ---- 复用主流程：由 TP 重新签发一份**子体专属**的 PHC ----
        #   ★ 身份因子只从**服务端自己登记的索引**里反查 —— 不接受调用方传入 H(ID)。
        #     子体的派生也必须由用户确认，如果 H(ID) 能由请求方指定，
        #     确认就成了「替别人点头」。
        issued = self.ctx.capability.issue_phc(IssueRequest(
            identity_hash=int(hid_hex, 16),
            tau=tau, crf=crf,
            apid_hex=material.ap_pubkey_hex,
            ap=material, requested_at=self.ctx.clock.now(),
            parent_did=req.parent_did,        # ★ AF 的入参，必须在签发时就给
        ))
        phc = issued.phc_json

        modules_src = [
            (mid, ver, self.ctx.modules.read_file(mid, ver, "engine.py"))
            for mid, ver, _ in resolved
        ]

        # ---- D6 变体：TP 给**唯一** DID ----
        #   ★ parent_did 不在这里写：它已经在 `issue_phc(parent_did=...)` 那一刻
        #     由 TP 锚进 AF 了。这里若再写一遍，等于让"AF 的入参"有两个来源，
        #     下一次有人改了一处、忘了另一处，就会重现「AF 锚定不一致」。
        #     单一来源是这段代码最重要的一行约定。
        sealed = self.ctx.capability.seal_did(SealDidRequest(
            phc_json=phc, parent_did=req.parent_did, did_namespace="sub",
            ap=material, requested_at=self.ctx.clock.now(),
        ))
        did = sealed.did
        if did in {"", req.parent_did}:
            raise IssueRejected("TP 返回的 DID 与父体冲突或为空 —— 子体必须有自己的唯一 DID")
        phc = sealed.phc_json

        # ---- 算法1：子体的 CMI 同样由 AP 自己写进 APM ----
        #   不做这一步的话，子体 PHC 里 APM.CMI 是空的：凭证上承诺了"这是哪份配置"，
        #   却没有真的承诺。子体与主体走的是完全一样的两步（签发 → 算法1 → 封印），
        #   差别只在 AF 里封入了 parent_did。
        phc = self.ctx.capability.write_cmi(WriteCmiRequest(
            phc_json=phc, cmi=cmi.value, apm_time=self.ctx.clock.now(),
            requested_at=self.ctx.clock.now(),
        ))
        final = self.ctx.capability.verify_phc(
            phc, identity_hash=int(hid_hex, 16), tau=tau, crf=crf)
        if not final.ok:
            raise IssueRejected("子体 PHC 终态校验未通过：" + "；".join(final.errors))

        expires_at = self.ctx.clock.plus_hours(req.ttl_hours)
        owner_did = parent.owner_did          # 归谁管仍是自然人的主 DID，不是父体

        store = self.ctx.agents
        store.save_meta(AgentMeta(
            did=did, agent_type=AgentType.SUB, owner_did=owner_did,
            identity_hash="",                 # 与主体同理：实例目录只认 DID
            created_at=self.ctx.clock.now(),
            parent_did=req.parent_did, state=AgentState.ACTIVE,
            expires_at=expires_at, ecid=issued.ecid,
        ))
        store.save_selection(did, StoreSelection(items=[
            {"module_id": c.module_id, "version": c.version}
            for c in req.selection.normalized()
        ]))
        store.save_cmi(did, StoreCmiRecord(
            cmi=cmi.value, layers=[l.chain for l in cmi.layers],
            computed_at=self.ctx.clock.now(),
            module_digests=[l.digest for l in cmi.layers],
        ))

        build = assemble(
            did=did, agent_type="sub", parent_did=req.parent_did,
            modules=modules_src, cmi=cmi.value,
            layer_chains=[l.chain for l in cmi.layers],
            ecid=issued.ecid, version=1,
        )
        store.write_build(did, 1, build.files)
        store.append_version(did, {
            "version": 1, "cmi": cmi.value, "at": self.ctx.clock.now(),
            "reason": "subagent-derivation",
            "confirmedAt": req.confirmation.confirmed_at,
            "buildDigest": build.build_digest(),
        })
        self._save_phc(did, phc)

        # ---- 索引：子体也挂在同一个 H(ID) 下（找回时一并列出）----
        self.ctx.identity_index.add(
            hid_hex, did,
            sealer=self.ctx.sealer(), opener=self.ctx.opener())
        self.ctx.owner_index.add(owner_did, did)

        # ---- 令牌用掉即废：同一张票不能派生第二个子体 ----
        self._consume_ticket(req.confirmation.token)

        _ = parent_phc   # 已在上方完成状态校验，此处保留引用便于审计挂接
        return DeriveResult(
            did=did, phc_json=phc, cmi=cmi.value,
            parent_did=req.parent_did, expires_at=expires_at,
            build_digest=build.build_digest(),
        )

    # ------------------------------------------------------------------
    # 确认令牌的一次性台账
    # ------------------------------------------------------------------
    def _ticket_path(self):
        return self.ctx.layout.index_dir / "confirmations.json"

    def _pending_path(self):
        return self.ctx.layout.index_dir / "pending-confirmations.json"

    @staticmethod
    def _load_json(p) -> dict:
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    @staticmethod
    def _save_json(p, data: dict) -> None:
        from localstore.paths import write_atomic
        write_atomic(p, json.dumps(data, ensure_ascii=False, indent=2).encode())

    def _load_tickets(self) -> dict:
        return self._load_json(self._ticket_path())

    def confirm(self, *, token: str, ticket: ConfirmationTicket):
        """用户手动确认：生成一次性令牌并登记。这是唯一会产生令牌的入口。

        ★ 只认 `prepare` 登记过的任务，且父体 / 方案摘要 / 有效期必须与登记时一致。
          一张任务只能确认一次 —— 否则同一次"点头"能换出任意多张令牌。
        """
        from ..entities import ConfirmToken

        if ticket.selection_digest == "":
            raise NotConfirmed("确认任务缺少方案摘要")
        with _LEDGER_LOCK:
            pending = self._load_json(self._pending_path())
            entry = pending.get(ticket.ticket_id)
            if entry is None:
                raise NotConfirmed("确认任务不存在 —— 必须先经 prepare 生成")
            if entry.get("confirmedAt"):
                raise NotConfirmed("该确认任务已确认过，请重新发起")
            if (entry["parentDid"], entry["selectionDigest"], int(entry["ttlHours"])) != (
                    ticket.parent_did, ticket.selection_digest, int(ticket.ttl_hours)):
                raise NotConfirmed("确认内容与 prepare 登记的方案不一致（父体 / 方案 / 有效期）")

            data = self._load_tickets()
            if token in data:
                raise NotConfirmed("令牌重复 —— 每次确认都必须生成新令牌")
            tok = ConfirmToken(
                token=token,
                selection_digest=ticket.selection_digest,
                confirmed_at=self.ctx.clock.now(),
            )
            data[token] = {
                "parentDid": ticket.parent_did,
                "ticketId": ticket.ticket_id,
                "selectionDigest": ticket.selection_digest,
                "confirmedAt": tok.confirmed_at,
                "consumedAt": "",
            }
            entry["confirmedAt"] = tok.confirmed_at
            # 先登记令牌、再标记任务：崩在中间最多留一张"任务未标记"的令牌，
            # 下一次 confirm 会被"令牌重复/任务已确认"之一拦下，不会多发
            self._save_json(self._ticket_path(), data)
            self._save_json(self._pending_path(), pending)
        return tok

    def load_ticket(self, token: str):
        data = self._load_tickets().get(token)
        if data is None:
            return None
        from ..entities import ConfirmToken
        return ConfirmToken(
            token=token, selection_digest=data["selectionDigest"],
            confirmed_at=data["confirmedAt"], consumed_at=data.get("consumedAt", ""),
        )

    def _consume_ticket(self, token: str) -> None:
        """把令牌标记为已用。读-改-写在锁内完成 —— 否则并发两次请求都能通过。"""
        with _LEDGER_LOCK:
            data = self._load_tickets()
            entry = data.get(token)
            if entry is None:
                raise NotConfirmed("确认令牌不存在（未经确认，或已被撤销）")
            if entry.get("consumedAt"):
                raise NotConfirmed("确认令牌已被使用")
            entry["consumedAt"] = self.ctx.clock.now()
            self._save_json(self._ticket_path(), data)

    def _token_parent(self, token: str) -> str:
        entry = self._load_tickets().get(token) or {}
        return entry.get("parentDid", "")

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    def _assert_selection_available(self, sel: Selection) -> None:
        for c in sel.choices:
            try:
                e = self.ctx.modules.get_entry(c.module_id, c.version)
            except FileNotFoundError as exc:
                raise IssueRejected(f"模块不存在：{c.module_id}@{c.version}") from exc
            if e.revoked:
                raise IssueRejected(f"模块已下架：{c.module_id}@{c.version}")

    def _resolve(self, sel: Selection):
        out = []
        for c in sel.normalized():
            e = self.ctx.modules.get_entry(c.module_id, c.version)
            if e.revoked:
                raise IssueRejected(f"模块已下架：{c.module_id}@{c.version}")
            out.append((c.module_id, c.version, e.digest))
        return out

    def _public_material(self) -> PublicKeyMaterial:
        hsm = self.ctx.ap_hsm
        return PublicKeyMaterial(
            ap_pubkey_hex=crypto.sdk.ser_point(hsm.pubkey()).hex(),
            ap_chameleon_cpk_hex=crypto.sdk.ser_point(hsm.chameleon_cpk()).hex(),
            tp_pubkey_hex="", tp_chameleon_cpk_hex="",
        )

    def _load_parent_phc(self, did: str) -> dict:
        p = self.ctx.layout.agent_dir(did) / "phc.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}

    def _hid_of(self, did: str) -> str:
        """从加密索引反查这个 DID 属于哪个 H(ID)。

        查不到就**拒**，不补一个空值往下走：H(ID) 是子体 AF 里最关键的锚，
        缺了它签出来的凭证要么验不过、要么验过但锚错了人 —— 后者更坏。
        """
        hid = self.ctx.identity_index.find_by_did(did, opener=self.ctx.opener())
        if not hid:
            raise IssueRejected(
                f"{did} 未在身份索引中登记 —— 无法确认它归属于谁，拒绝派生")
        return hid

    def _save_phc(self, did: str, phc: dict) -> None:
        from localstore.paths import write_atomic
        write_atomic(self.ctx.layout.agent_dir(did) / "phc.json",
                     json.dumps(phc, ensure_ascii=False, indent=2).encode())


__all__ = ["DeriveSubAgentUseCase", "ConfirmationTicket", "DeriveResult"]
