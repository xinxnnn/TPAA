"""承接吊销广播：把网络来的停运令转成本地停运。

★ 案由必填，这是**第三道**校验：

    policy-service 签发吊销令时查了一次（没有案由就不签发）。
    lifecycle-service 执行时又查了一次（"广播来自网络，不能只信上游校验过"）。
    这里再查一次，不是重复劳动 ——
    前两道都在进程内，可以被一次代码改动同时绕过；
    这一道在**真正的网络边界**上，绕过它得先打穿网络。

    三道校验分布在三个信任域里，才叫三道。挤在同一个进程里只算一道。

★ 为什么 `stop` 端口可以是 None：
    不是每个 AP 节点都承接吊销。一个纯协查节点（只应答不给实例停运）
    装配时就不该有 stop —— 让它有，等于给它一份它用不到也解释不了的能力。
    缺了就明确拒，而不是"悄悄什么都不做"。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import BadNotice, IntakeResult


@dataclass(frozen=True)
class RevocationCommand:
    root_did: str
    revoked: list = ()
    case_ref: str = ""
    reason: str = ""


class IntakeRevocationUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RevocationCommand) -> IntakeResult:
        root = (cmd.root_did or "").strip()
        case_ref = (cmd.case_ref or "").strip()

        if not root:
            raise BadNotice("吊销广播缺少 rootDid")
        if not case_ref:
            raise BadNotice(
                "吊销广播缺少案由 —— 拒绝承接。"
                "无案由的停运令无法在事后解释'为什么停'，"
                "而'说不清为什么'的停运本身就是一次事故")
        if self.ctx.stop is None:
            raise BadNotice(
                "本节点未装配停运能力（stop 端口缺失）—— "
                "这是一台纯协查节点，吊销广播应发往持有该实例的节点")

        revoked = [str(d) for d in (cmd.revoked or []) if str(d).strip()]

        try:
            out = self.ctx.stop.stop(root_did=root, revoked=revoked,
                                     case_ref=case_ref, reason=cmd.reason or "")
        except Exception as exc:                      # noqa: BLE001
            self._audit("gateway.revocation_failed", root,
                        {"caseRef": case_ref, "reason": str(exc),
                         "revokedCount": len(revoked)})
            raise

        result = IntakeResult(
            root_did=root, stopped=list(out.stopped), already=list(out.already),
            not_local=list(out.not_local), case_ref=case_ref)

        self._audit("gateway.revocation", root,
                    {"caseRef": case_ref, "stopped": len(result.stopped),
                     "already": len(result.already),
                     "notLocal": len(result.not_local)})
        return result

    def _audit(self, kind: str, subject: str, payload: dict) -> None:
        try:
            self.ctx.audit.append(kind=kind, subject=subject, payload=payload)
        except Exception:                             # noqa: BLE001
            pass


__all__ = ["IntakeRevocationUseCase", "RevocationCommand", "IntakeResult"]
