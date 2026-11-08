"""四个端口的进程内实现（本地演练 / 单体部署）。

★ 这里 import 了同区其他服务的**用例**，这在纯分层视角下像是越界。
  但它正是"适配器"这个词的意思：把一次跨服务调用换成一次函数调用，
  而上层（domain）看到的仍然是同一个端口。真要分区部署时，
  换成 HTTP 客户端即可，domain 一行不用改 —— 这正是当初声明端口的理由。

★ 这些适配器**不缓存**任何东西。
  追溯最怕的就是拿到一份"上一次的"归属关系：DID 可以在两次查询之间被吊销。
"""

from __future__ import annotations

from dataclasses import dataclass

import crypto.sdk

from ..domain.ports import DidView, LineageView, TicketView


# ---------------------------------------------------------------------------
# did-service
# ---------------------------------------------------------------------------


class LocalDirectory:
    """把 did-service 的用例包装成 DirectoryPort。"""

    def __init__(self, did_ctx) -> None:
        from services.shared.modules import service_module

        self._uc = service_module("tp-side/did-service", "domain.usecases")
        self._ctx = did_ctx

    def resolve(self, did: str) -> DidView:
        rec = self._uc.ResolveDidUseCase(self._ctx).execute(did)
        return DidView(did=rec.did, parent_did=rec.parent_did,
                       agent_type=rec.agent_type, state=rec.state.value,
                       ecid_ref=rec.ecid_ref)

    def reveal_cscid(self, did: str, *, case_ref: str, requested_by: str) -> str:
        out = self._uc.RevealCscidUseCase(self._ctx).execute(
            self._uc.RevealCommand(did=did, case_ref=case_ref,
                                   requested_by=requested_by))
        return out.cscid

    def trace(self, did: str) -> LineageView:
        lin = self._uc.TraceLineageUseCase(self._ctx).execute(did)
        return LineageView(chain=list(lin.chain), root=lin.root, depth=lin.depth)


# ---------------------------------------------------------------------------
# coordination
# ---------------------------------------------------------------------------


class LocalChannel:
    def __init__(self, coord_ctx) -> None:
        from services.shared.modules import service_module

        self._uc = service_module("cross-domain/coordination", "domain.usecases")
        self._ctx = coord_ctx

    def open(self, *, requester: str, responder: str, kind: str,
             payload: dict, case_ref: str) -> str:
        t = self._uc.OpenTicketUseCase(self._ctx).execute(
            requester=requester, responder=responder, kind=kind,
            payload=payload, case_ref=case_ref)
        return t.ticket_id

    def get(self, ticket_id: str) -> TicketView:
        t = self._uc.GetTicketUseCase(self._ctx).execute(ticket_id)
        return TicketView(ticket_id=t.ticket_id, state=t.state.value,
                          answer=dict(t.answer))


# ---------------------------------------------------------------------------
# IPFS
# ---------------------------------------------------------------------------


@dataclass
class IpfsByName:
    """凭 ECID 取回密文。

    ★ CID 只在本方法内部出现一次，随即丢弃（红线 17）。
      它不返回、不缓存、不写日志 —— 拿到 CID 就等于拿到"这条记录在 IPFS 上的门牌"。
    """

    storage: object
    ecid_key: bytes
    requester: str = "supervision-service"

    def fetch_by_ecid(self, ecid: str) -> bytes:
        cid = crypto.sdk.recover_cid(ecid, self.ecid_key)
        if cid is None:
            raise ValueError(
                "ECID 无法还原成 CID（密钥不匹配或 ECID 被改过）—— 取证中止")
        blob = self.storage.get(cid, requester=self.requester)
        if blob is None:
            raise ValueError(f"IPFS 上不存在该对象（CID 已失效或未被固定）—— 取证中止")
        return blob


# ---------------------------------------------------------------------------
# 审计
# ---------------------------------------------------------------------------


@dataclass
class LocalAudit:
    """把 append 交给 audit-service 的用例。"""

    audit_ctx: object

    def _uc(self):
        from services.shared.modules import service_module

        return service_module("cross-domain/audit-service", "domain.usecases")

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        uc = self._uc().RecordUseCase(self.audit_ctx)
        out = uc.execute(kind=kind, subject=subject, payload=payload)
        return out.entry_id

    def verify(self):
        """复算整条审计链。

        ★ 取证包里的"链已核验"必须是**现场算出来的**，不能是某个布尔标志。
          取证发生在立案之后、导出之前，中间可能有人动过账本 ——
          所以每次导出前重算一遍，算出来的结论才写进包里。
        """
        return self._uc().VerifyChainUseCase(self.audit_ctx).execute()

    def probe(self) -> tuple[bool, str]:
        try:
            n = len(self.audit_ctx.ledger.all())
        except Exception as exc:                     # noqa: BLE001
            return False, str(exc)
        return True, f"entries={n}"


__all__ = ["LocalDirectory", "LocalChannel", "IpfsByName", "LocalAudit"]
