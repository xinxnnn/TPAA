"""policy-service 的端口实现（进程内）。

★ 为什么 `revoke_with_cascade` 要绕到 did-service 去做：
    policy 决定"该不该吊销"，did-service 掌握"谁是后代"。
    让 policy 自己遍历关系，等于让它持有一份关系的副本 —— 副本一旧，级联就漏人。
    所以这里只是把命令递过去，不自己算。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.ports import CascadeResult


@dataclass
class LocalDirectory:
    did_ctx: object

    def _uc(self):
        from services.shared.modules import service_module

        return service_module("tp-side/did-service", "domain.usecases")

    def revoke_with_cascade(self, did: str, *, reason: str,
                            by: str) -> CascadeResult:
        uc = self._uc()
        out = uc.RevokeDidUseCase(self.did_ctx).execute(
            uc.RevokeCommand(did=did, reason=reason, by=by))
        return CascadeResult(root=out.root, revoked=list(out.revoked),
                             already_revoked=list(out.already_revoked))


@dataclass
class LocalNotify:
    """通知 AP 侧停运。

    ★ 真正的停运动作在 lifecycle-service（AP 侧）里 ——
      policy 无权直接改 AP 的 localstore，它只能"通知"。
      这条边界不是形式主义的：如果 policy 能手伸进 AP 的磁盘，
      "AP 侧自主管理其资产"这句话就不成立了。
    """

    lifecycle_ctx: object

    def _uc(self):
        from services.shared.modules import service_module

        return service_module("ap-side/lifecycle-service", "domain.usecases")

    def _ent(self):
        from services.shared.modules import service_module

        return service_module("ap-side/lifecycle-service", "domain.entities")

    def notify_revoked(self, *, root_did: str, revoked: list[str],
                       case_ref: str, reason: str) -> list[str]:
        uc = self._uc()
        out = uc.HandleRevocationUseCase(self.lifecycle_ctx).execute(
            self._ent().RevocationNotice(
                root_did=root_did, revoked=list(revoked),
                case_ref=case_ref, reason=reason))
        return list(out.stopped)


@dataclass
class LocalAudit:
    audit_ctx: object

    def _uc(self):
        from services.shared.modules import service_module

        return service_module("cross-domain/audit-service", "domain.usecases")

    def append(self, *, kind: str, subject: str, payload: dict) -> str:
        out = self._uc().RecordUseCase(self.audit_ctx).execute(
            kind=kind, subject=subject, payload=payload)
        return out.entry_id

    def probe(self) -> tuple[bool, str]:
        try:
            return True, f"entries={len(self.audit_ctx.ledger.all())}"
        except Exception as exc:                     # noqa: BLE001
            return False, str(exc)


__all__ = ["LocalDirectory", "LocalNotify", "LocalAudit"]
