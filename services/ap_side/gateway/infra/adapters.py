"""gateway 的四个端口实现。

★ 这里刻意提供**两套** ChannelPort：

    LocalChannel   进程内调用 coordination 的用例（单体部署 / 测试）
    HttpChannel    真发起 HTTP 请求到 coordination 的服务（分区部署）

  两者的 `pull` / `answer` 签名完全一样，domain 层一行不用改。
  这不是为了炫技 —— 而是因为 README 里那句"换适配器即可分区部署"
  一直只是句声明，从来没被执行过。这次把它跑通：
  `tests/integration/test_gateway_http.py` 用 HttpChannel 打一个
  真起在 TestClient 上的 coordination，走完整个收件→应答→回写。
"""

from __future__ import annotations

from dataclasses import dataclass


def _coord_usecases():
    from services.shared.modules import service_module

    return service_module("cross-domain/coordination", "domain.usecases")


def _coord_entities():
    from services.shared.modules import service_module

    return service_module("cross-domain/coordination", "domain.entities")


def _lifecycle_usecases():
    from services.shared.modules import service_module

    return service_module("ap-side/lifecycle-service", "domain.usecases")


def _lifecycle_entities():
    from services.shared.modules import service_module

    return service_module("ap-side/lifecycle-service", "domain.entities")


def _audit_usecases():
    from services.shared.modules import service_module

    return service_module("cross-domain/audit-service", "domain.usecases")


# ---------------------------------------------------------------------------
# ChannelPort —— 进程内
# ---------------------------------------------------------------------------


@dataclass
class LocalChannel:
    """把 coordination 的用例包装成 ChannelPort。"""

    coord_ctx: object

    def pull(self, *, responder: str, state: str = "pending",
             limit: int = 100) -> list:
        from ..domain.entities import InboxTicket

        uc = _coord_usecases()
        got = uc.ListTicketsUseCase(self.coord_ctx).execute(
            uc.ListCommand(responder=responder, state=state, limit=limit))
        return [InboxTicket(ticket_id=t.ticket_id, kind=t.kind,
                            payload=dict(t.payload or {}), case_ref=t.case_ref)
                for t in got]

    def answer(self, *, ticket_id: str, responder: str, answer: dict) -> dict:
        uc = _coord_usecases()
        out = uc.AnswerTicketUseCase(self.coord_ctx).execute(
            ticket_id=ticket_id, responder=responder, answer=answer)
        return {"state": out.state, "answeredAt": out.answered_at}

    def probe(self) -> tuple:
        try:
            n = len(self.coord_ctx.tickets.all())
        except Exception as exc:                     # noqa: BLE001
            return False, str(exc)
        return True, f"tickets={n}"


# ---------------------------------------------------------------------------
# ChannelPort —— 真 HTTP
# ---------------------------------------------------------------------------


class ChannelUnavailable(RuntimeError):
    """对岸不可达或拒绝。附带 status，便于上层判断是否值得重试。"""

    def __init__(self, message: str, *, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class HttpChannel:
    """经 HTTP 访问 coordination。

    ★ 这个适配器是"分区部署"这句话的全部证据。
      domain 层看到的是同一个 ChannelPort，不知道底下是函数调用还是一次网络往返。

    ★ 它**不重试**。
      重试策略属于编排层（谁决定等多久、要不要退避），不该埋在适配器里。
      一次失败就如实抛回去，让调用方看得见"这次没成"。
    """

    base_url: str
    timeout: float = 5.0
    client: object = None          # 可注入 httpx.Client / TestClient

    def _request(self, method: str, path: str, **kw) -> dict:
        """发一次请求。注入了 client 就复用它（测试里是 TestClient）。"""
        if self.client is not None:
            return self._do(self.client, method, path, **kw)
        import httpx

        with httpx.Client(base_url=self.base_url, timeout=self.timeout) as http:
            return self._do(http, method, path, **kw)

    def _do(self, http, method: str, path: str, **kw) -> dict:
        try:
            resp = http.request(method, path, **kw)
        except Exception as exc:                     # noqa: BLE001
            raise ChannelUnavailable(
                f"跨域通道不可达：{exc}", status=0) from exc

        if resp.status_code >= 400:
            try:
                body = resp.json()
                detail = body.get("message") or body.get("detail") or ""
            except Exception:                        # noqa: BLE001
                detail = getattr(resp, "text", "")[:200]
            raise ChannelUnavailable(
                f"跨域通道拒绝（{resp.status_code}）：{detail}",
                status=resp.status_code)
        try:
            return resp.json()
        except Exception as exc:                     # noqa: BLE001
            raise ChannelUnavailable(
                f"跨域通道返回了非 JSON：{exc}", status=resp.status_code) from exc

    def pull(self, *, responder: str, state: str = "pending",
             limit: int = 100) -> list:
        from ..domain.entities import InboxTicket

        data = self._request(
            "GET", "/v1/tickets",
            params={"responder": responder, "state": state, "limit": limit})
        return [InboxTicket.from_json(t) for t in (data.get("tickets") or [])]

    def answer(self, *, ticket_id: str, responder: str, answer: dict) -> dict:
        return self._request(
            "POST", f"/v1/tickets/{ticket_id}/answer",
            json={"responder": responder, "answer": answer})

    def probe(self) -> tuple:
        try:
            data = self._request("GET", "/healthz")
        except ChannelUnavailable as exc:
            return False, str(exc)
        problems = data.get("problems") or []
        if problems:
            return False, "; ".join(str(p) for p in problems)
        return True, f"remote={data.get('service', 'coordination')}"


# ---------------------------------------------------------------------------
# AssistPort / StopPort —— 委托 lifecycle
# ---------------------------------------------------------------------------


@dataclass
class LocalAssist:
    """把 lifecycle 的协查应答包装成 AssistPort。

    ★ 不吞异常：lifecycle 抛什么就往上抛什么。
      gateway 会把它翻译成 not_local，但**原文只进审计、不出网** ——
      翻译发生在用例里，不在这里，否则适配器就替 domain 做了决定。
    """

    lifecycle_ctx: object

    def answer_assist(self, *, kind: str, payload: dict) -> dict:
        uc = _lifecycle_usecases()
        out = uc.AnswerAssistUseCase(self.lifecycle_ctx).execute(
            kind=kind, payload=payload)
        return dict(out.answer)

    def probe(self) -> tuple:
        try:
            errs = self.lifecycle_ctx.preflight()
        except Exception as exc:                     # noqa: BLE001
            return False, str(exc)
        return (False, "; ".join(errs)) if errs else (True, "lifecycle ok")


@dataclass
class LocalStop:
    """把 lifecycle 的停运包装成 StopPort。"""

    lifecycle_ctx: object

    def stop(self, *, root_did: str, revoked: list, case_ref: str,
             reason: str):
        uc = _lifecycle_usecases()
        notice = _lifecycle_entities().RevocationNotice(
            root_did=root_did, revoked=list(revoked), case_ref=case_ref,
            reason=reason)
        out = uc.HandleRevocationUseCase(self.lifecycle_ctx).execute(notice)
        from ..domain.ports import StopOutcome

        return StopOutcome(stopped=list(out.stopped), already=list(out.already),
                           not_local=list(out.not_local))


# ---------------------------------------------------------------------------
# AuditSink
# ---------------------------------------------------------------------------


@dataclass
class LocalAudit:
    audit_ctx: object

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        return _audit_usecases().RecordUseCase(self.audit_ctx).execute(
            kind=kind, subject=subject, payload=payload).entry_id

    def probe(self) -> tuple:
        try:
            n = len(self.audit_ctx.ledger.all())
        except Exception as exc:                     # noqa: BLE001
            return False, str(exc)
        return True, f"entries={n}"


__all__ = ["LocalChannel", "HttpChannel", "ChannelUnavailable", "LocalAssist",
           "LocalStop", "LocalAudit"]
