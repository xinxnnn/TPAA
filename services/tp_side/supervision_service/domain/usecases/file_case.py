"""立案与不予受理。

★ 这是整个系统里权限最重的一次点击。
  它之后，一个自然人可以被还原、可以关联、可以被吊销。
  所以它要求两个不同的签字人，并且拒绝"同一个人签两次"。

★ 拒绝路径同样要留痕。
  一个只有"通过"记录的系统，事后无法解释"为什么这个案子没查" ——
  而不予受理本身就是一个需要被解释的决定。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import CaseError, CaseState


@dataclass(frozen=True)
class FileCommand:
    case_id: str
    reviewers: list[str]
    note: str = ""


@dataclass(frozen=True)
class FileResult:
    case_id: str
    subject_did: str
    state: str
    filed_at: str
    reviewers: list[str]


class FileCaseUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: FileCommand) -> FileResult:
        case = self.ctx.cases.get(cmd.case_id)
        if case is None:
            raise CaseError(f"案件 {cmd.case_id} 不存在")

        # 已经立过案的，允许重复调用并返回同一结果（幂等），
        # 但**不允许**改签字人 —— 否则"谁批准的"就变成了可编辑字段。
        if case.state is not CaseState.REPORTED:
            if case.state is CaseState.FILED or case.state in (
                    CaseState.INVESTIGATING, CaseState.DISCLOSED,
                    CaseState.SEALED, CaseState.REVOKED):
                return FileResult(case_id=case.case_id,
                                  subject_did=case.subject_did,
                                  state=case.state.value, filed_at=case.filed_at,
                                  reviewers=list(case.reviewers))
            raise CaseError(f"案件 {case.case_id} 当前为 {case.state.value}，不能立案")

        now = self.ctx.clock.now()
        case.file(reviewers=cmd.reviewers, note=cmd.note, at=now)
        self.ctx.cases.put(case)

        self.ctx.audit.append(
            kind="case.filed", subject=case.case_id,
            payload={"caseRef": case.case_id, "subjectDid": case.subject_did,
                     "reviewers": case.reviewers, "note": case.reviewers_note},
        )
        return FileResult(case_id=case.case_id, subject_did=case.subject_did,
                          state=case.state.value, filed_at=now,
                          reviewers=list(case.reviewers))


class RejectCaseUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_id: str, reviewer: str, note: str) -> FileResult:
        case = self.ctx.cases.get(case_id)
        if case is None:
            raise CaseError(f"案件 {case_id} 不存在")
        if case.state is not CaseState.REPORTED:
            raise CaseError(f"案件 {case_id} 当前为 {case.state.value}，不能再驳回")
        if not note.strip():
            raise ValueError("不予受理必须写明理由 —— 这是一个需要被解释的决定")

        case.reject(note=f"{reviewer}: {note}")
        self.ctx.cases.put(case)
        self.ctx.audit.append(
            kind="case.rejected", subject=case_id,
            payload={"caseRef": case_id, "reviewer": reviewer, "note": note})
        return FileResult(case_id=case_id, subject_did=case.subject_did,
                          state=case.state.value, filed_at="", reviewers=[])


__all__ = ["FileCommand", "FileResult", "FileCaseUseCase", "RejectCaseUseCase"]
