"""举报受理。

举报是**任何人都能发起**的动作，所以它必须极其便宜、极其无权限。
同时它也是全系统唯一一个"外部输入直接进审计链"的入口 ——
因此有一件事必须做对：**举报本身不构成对任何人的指控**。

代码上的体现是：受理时只记录，不解密、不查询、不联系 AP。
一旦举报就能触发查证，通道会立刻变成骚扰工具。
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from ..entities import Case, CaseState

_MIN_EVIDENCE_LEN = 8


@dataclass(frozen=True)
class ReportCommand:
    subject_did: str
    reporter: str
    allegation: str
    evidence_ref: str = ""


@dataclass(frozen=True)
class ReportResult:
    case_id: str
    subject_did: str
    state: str
    reported_at: str


class ReportCaseUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: ReportCommand) -> ReportResult:
        if not cmd.subject_did.strip():
            raise ValueError("举报必须指明被举报的 DID")
        if len(cmd.allegation.strip()) < 4:
            raise ValueError("举报必须写明事由（至少 4 个字）")
        if not cmd.reporter.strip():
            raise ValueError("举报必须留下举报人标识（可匿名，但要有标识以便追询）")

        # 被举报的 DID 必须真实存在 —— 对着不存在的号立案，
        # 后续每一步都会以"查不到"告终，白耗一次人工复核。
        view = self.ctx.directory.resolve(cmd.subject_did)

        now = self.ctx.clock.now()
        case_id = "case-" + hashlib.sha256(
            f"{cmd.subject_did}|{now}|{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

        case = Case(
            case_id=case_id, subject_did=view.did, reporter=cmd.reporter.strip(),
            evidence_ref=cmd.evidence_ref.strip(),
            allegation=cmd.allegation.strip(),
            state=CaseState.REPORTED, reported_at=now,
        )
        self.ctx.cases.put(case)

        self.ctx.audit.append(
            kind="case.reported", subject=case_id,
            payload={"caseRef": case_id, "subjectDid": view.did,
                     "reporter": case.reporter,
                     "evidenceRef": case.evidence_ref},
        )
        return ReportResult(case_id=case_id, subject_did=view.did,
                            state=case.state.value, reported_at=now)


__all__ = ["ReportCommand", "ReportResult", "ReportCaseUseCase"]
