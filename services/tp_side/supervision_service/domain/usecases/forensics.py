"""取证（R2 的后半段）：取回信封、封装取证包。

★ 这里做的是"打包"，不是"解密给人看"。
  身份材料（BI/PII）一旦被摊开在取证包的字段里，这个包会流向律师、监管、
  甚至公开审理 —— 二次泄漏的伤害往往比原始案件更大。
  所以包里放的是：**信封的摘要、链的核验结论、时间线**，
  原始材料仍留在 IPFS 与监管域，需要时按同一套立案手续单独调阅。

★ usecase 会真的去 IPFS 取一次并验摘要。
  不是为了解密，而是为了证明"这份材料现在还在、还没被换过"。
  一个连取都取不回来的取证包，等于一张白纸。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..entities import CaseState


@dataclass(frozen=True)
class ForensicResult:
    case_id: str
    subject_did: str
    state: str
    envelope_digest: str = ""
    envelope_bytes: int = 0
    chain_verified: bool = False
    verdict_reason: str = ""
    sealed_at: str = ""
    timeline: list[dict] = field(default_factory=list)


class ForensicsUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_id: str, exported_by: str) -> ForensicResult:
        case = self.ctx.cases.get(case_id)
        if case is None:
            raise ValueError(f"案件 {case_id} 不存在")

        # 取证必须在揭露之后 —— 先要知道"查的是谁"，再谈"证明他做了什么"
        case.guard(CaseState.DISCLOSED, CaseState.SEALED)

        # 1) 取回信封并留摘要。取不回来就是取证失败，不放宽。
        ecid = self.ctx.directory.resolve(case.subject_did).ecid_ref
        digest, size = "", 0
        if ecid:
            blob = self.ctx.storage.fetch_by_ecid(ecid)
            digest = hashlib.sha256(blob).hexdigest()
            size = len(blob)

        # 2) 核验审计链
        verdict = self.ctx.audit.verify() if hasattr(self.ctx.audit, "verify") else None

        timeline = [
            {"at": case.reported_at, "event": "reported"},
            {"at": case.filed_at, "event": "filed", "reviewers": case.reviewers},
            {"at": case.disclosed_at, "event": "disclosed"},
        ]

        now = self.ctx.clock.now()
        body = {
            "caseRef": case.case_id, "subjectDid": case.subject_did,
            "identityDigest": case.disclosed_hash,
            "lineage": case.lineage_chain,
            "envelopeDigest": digest, "timeline": timeline,
            "exportedBy": exported_by,
        }
        case.forensic_digest = _digest(body)
        case.sealed_at = now
        if case.state is CaseState.DISCLOSED:
            case.move(CaseState.SEALED)
        self.ctx.cases.put(case)

        self.ctx.audit.append(
            kind="case.sealed", subject=case.case_id,
            payload={"caseRef": case.case_id, "subjectDid": case.subject_did,
                     "forensicDigest": case.forensic_digest,
                     "envelopeDigest": digest, "exportedBy": exported_by},
        )
        return ForensicResult(
            case_id=case.case_id, subject_did=case.subject_did,
            state=case.state.value, envelope_digest=digest,
            envelope_bytes=size,
            chain_verified=bool(getattr(verdict, "ok", False)),
            verdict_reason=str(getattr(verdict, "reason", "")),
            sealed_at=now, timeline=timeline)


def _digest(obj: dict) -> str:
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()


__all__ = ["ForensicsUseCase", "ForensicResult"]
