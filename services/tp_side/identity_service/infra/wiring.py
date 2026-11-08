"""identity-service 装配。TP 的 HSM 由部署注入（演练时由调用方生成后传入）。"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.shared.store import JsonStore
from services.shared.v1_http import SystemClock


@dataclass(frozen=True)
class IdentityEvidencePolicy:
    """Trusted verifier keys are injected by deployment, never taken from a CR."""

    trusted_issuers: dict[str, str]
    min_assurance: str = "substantial"

    def __post_init__(self) -> None:
        if not self.trusted_issuers:
            raise ValueError("正式身份受理必须配置信任的核验签发方")
        if self.min_assurance not in ("basic", "substantial", "high"):
            raise ValueError("身份核验最低保证级别无效")


@dataclass
class IdentityContext:
    tp_hsm: object
    store: JsonStore
    clock: object = field(default_factory=SystemClock)
    audit_log: list = field(default_factory=list)
    app_state: object | None = None
    review: object | None = None
    review_status: dict = field(default_factory=dict)
    demo_photo_preview: bool = False
    identity_policy: IdentityEvidencePolicy | None = None
    test_adapter: bool = False

    def progress_review(self, app_id: str):
        if self.review is not None:
            try:
                return self.review.status(app_id)
            except LookupError:
                return None
        return self.review_status.get(app_id)

    def audit(self, kind: str, subject: str, payload: dict) -> None:
        # 只记摘要与申请号；接审计服务时换成 audit-service 端口
        self.audit_log.append({"kind": kind, "subject": subject, "payload": payload,
                               "at": self.clock.now()})


def build_context(*, tp_hsm, db_path: str, clock=None,
                  demo_photo_preview: bool = False,
                  identity_policy: IdentityEvidencePolicy | None = None,
                  test_adapter: bool = False) -> IdentityContext:
    if getattr(tp_hsm, "domain", None) != "TP":
        raise RuntimeError("identity-service 需要 TP 域的 HSM")
    if not test_adapter and identity_policy is None:
        raise RuntimeError("正式身份受理必须注入身份核验策略；演练须显式 test_adapter=True")
    return IdentityContext(tp_hsm=tp_hsm, store=JsonStore(db_path), clock=clock or SystemClock(),
                           demo_photo_preview=demo_photo_preview,
                           identity_policy=identity_policy, test_adapter=test_adapter)


__all__ = ["IdentityContext", "IdentityEvidencePolicy", "build_context"]
