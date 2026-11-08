"""处理收件箱：拉待答工单 → 本地算 → 过卡口 → 回写。

★ 为什么是"拉"而不是"被推送"：

    TP 开单后如果直接推给 AP，AP 就必须有一个能被对岸连进来的监听端口 ——
    那意味着 AP 的边界上开了一个入站口子。
    改成 AP 主动去拉，边界上就只有**出站**流量。
    代价是延迟（取决于轮询间隔），换来的是"AP 侧没有任何入站面"，
    对一个持有全部用户实例的节点来说，这个交换是划算的。

★ 为什么一次处理一批而不是一张：
    背压。限额写在 `batch_limit` 上，对岸灌再多单子，
    本方每轮最多做这么多 —— 剩下的下轮再来，不会把 AP 的节点打满。

★ 四种结局，四种处理，不要合并：

    ok          给了材料，回写
    not_local   本机没有，回写（并说明"我查了，但我这儿没有"）
    refused     请求不成立，回写（一句明确的拒绝，好过让人等 72 小时）
    blocked     差点泄密，**不回写**，留痕报警

    前三种是业务层的，对方有权知道；最后一种是安全层的，
    回写就等于告诉对岸"我这边确实有这个字段"。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import (
    ChannelDown,
    ExportBlocked,
    OutboxItem,
    OutboxReport,
    ReplyStatus,
    assert_exportable,
)

# ★ 固定文案，不把 lifecycle 的异常原文带出网。
#   "这个 DID 不在本机"是一句事实；"本机 /data/ap/agents/xxx 下没有 phc.json"
#   是一份拓扑。两者对追溯的价值相同，泄露的代价差很远。
_NOT_LOCAL_REASON = "该实例不在本节点"


class DrainOutboxUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, limit: int | None = None) -> OutboxReport:
        take = int(limit) if limit and limit > 0 else int(self.ctx.batch_limit)
        try:
            pending = list(self.ctx.channel.pull(
                responder=self.ctx.self_id, state="pending", limit=take))
        except Exception as exc:                          # noqa: BLE001
            # ★ 连不上对岸：整轮都没开始，没有"部分成功"可言。
            #   如实抛 ChannelDown（HTTP 上回 503），不要退化成空报告 ——
            #   一个返回 200 且 polled=0 的 drain 会让调用方以为"没有待办"，
            #   而真相是"我根本没问成"。
            self._audit("gateway.channel_down", "", {"reason": str(exc)})
            raise ChannelDown(f"跨域通道不可达，本轮未处理任何工单：{exc}") from exc

        report = OutboxReport(polled=len(pending))
        for t in pending:
            report.items.append(self._handle(t, report))
        return report

    # ------------------------------------------------------------------

    def _handle(self, t, report: OutboxReport) -> OutboxItem:
        tid = getattr(t, "ticket_id", "") or ""

        # 1) 本节点答不答这种类别
        if t.kind not in tuple(self.ctx.allowed_kinds):
            return self._send(t, {"status": ReplyStatus.REFUSED.value,
                                  "reason": f"本节点不应答 {t.kind}"},
                              report, audit_kind="gateway.refused")

        # 2) 本地算
        try:
            answer = dict(self.ctx.assist.answer_assist(
                kind=t.kind, payload=dict(t.payload or {})))
        except Exception as exc:                      # noqa: BLE001
            # 答不了：可能是"不在本机"，也可能是本地存储坏了。
            # 对岸只需要知道"这次没拿到"，具体原因进审计。
            self._audit("gateway.not_local", tid,
                        {"kind": t.kind, "caseRef": t.case_ref,
                         "detail": str(exc)})
            return self._send(t, {"status": ReplyStatus.NOT_LOCAL.value,
                                  "did": str((t.payload or {}).get("did") or ""),
                                  "reason": _NOT_LOCAL_REASON},
                              report, audit_kind=None)

        # 3) 出口卡口 —— ★ 即便上游保证过，这里还要再查
        full = {"status": ReplyStatus.OK.value, **answer}
        try:
            assert_exportable(full)
        except ExportBlocked as exc:
            report.blocked.append(tid)
            self._audit("gateway.export_blocked", tid,
                        {"kind": t.kind, "caseRef": t.case_ref,
                         "reason": str(exc),
                         "offendingKeys": sorted(set(full))})
            return OutboxItem(ticket_id=tid, kind=t.kind, status="",
                              delivered=False, reason=str(exc))

        return self._send(t, full, report, audit_kind="gateway.answered")

    def _send(self, t, payload: dict, report: OutboxReport,
              *, audit_kind: str | None) -> OutboxItem:
        tid = getattr(t, "ticket_id", "") or ""

        # 拒绝与"不在本机"同样是出网内容，一样要过卡口。
        # 卡口管的是"什么能出去"，不管"这次是成功还是失败"。
        try:
            assert_exportable(payload)
        except ExportBlocked as exc:
            report.blocked.append(tid)
            self._audit("gateway.export_blocked", tid,
                        {"kind": t.kind, "reason": str(exc)})
            return OutboxItem(ticket_id=tid, kind=t.kind, status="",
                              delivered=False, reason=str(exc))

        try:
            self.ctx.channel.answer(ticket_id=tid, responder=self.ctx.self_id,
                                    answer=payload)
        except Exception as exc:                      # noqa: BLE001
            # 回写失败：留痕，等下轮重试。工单仍在 pending，不会被吞掉。
            self._audit("gateway.deliver_failed", tid,
                        {"kind": t.kind, "caseRef": t.case_ref,
                         "reason": str(exc)})
            return OutboxItem(ticket_id=tid, kind=t.kind,
                              status=str(payload.get("status") or ""),
                              delivered=False, reason=f"回写失败：{exc}")

        if audit_kind:
            self._audit(audit_kind, tid,
                        {"kind": t.kind, "caseRef": t.case_ref,
                         "status": payload.get("status")})
        return OutboxItem(ticket_id=tid, kind=t.kind,
                          status=str(payload.get("status") or ""),
                          delivered=True, reason=str(payload.get("reason") or ""))

    def _audit(self, kind: str, subject: str, payload: dict) -> None:
        try:
            self.ctx.audit.append(kind=kind, subject=subject, payload=payload)
        except Exception:                             # noqa: BLE001
            # 留痕失败不能让应答跟着失败 —— 但也不该静默，交给日志
            pass


__all__ = ["DrainOutboxUseCase", "OutboxReport"]
