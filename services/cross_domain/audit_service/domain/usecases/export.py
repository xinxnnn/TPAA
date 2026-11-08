"""链核验与取证导出。

取证包要能被**第三方**看懂，所以它必须自带三样东西：

    1  记录本身（谁在什么时候做了什么）
    2  链的核验结论（以及核验方法：从第一条复算到第 n 条）
    3  整包的摘要（便于比对"你手上这份和我导出那份是不是同一份"）

★ 导出**不附带任何密钥、不附带 H(ID) 明文**。
  取证包会被发给律师、监管、甚至公众，它一旦泄漏就是二次伤害。
  需要证明"这个 DID 属于某自然人"时，走的是监管域当场还原，而不是把它写进包里。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..entities import ChainVerdict, canonical, digest_of, verify_entries


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    length: int
    broken_at: int = -1
    reason: str = ""

    @classmethod
    def of(cls, v: ChainVerdict) -> "VerifyResult":
        return cls(ok=v.ok, length=v.length, broken_at=v.broken_at, reason=v.reason)


@dataclass(frozen=True)
class Bundle:
    case_ref: str
    entries: list[dict] = field(default_factory=list)
    verdict: VerifyResult | None = None
    bundle_digest: str = ""
    exported_at: str = ""

    def to_json(self) -> dict:
        return {
            "caseRef": self.case_ref,
            "exportedAt": self.exported_at,
            "entries": self.entries,
            "verification": (self.verdict.__dict__ if self.verdict else None),
            "bundleDigest": self.bundle_digest,
            "note": ("本包不含任何密钥与身份明文；"
                     "链可由第三方从第 1 条起用 sha256 独立复算"),
        }


class VerifyChainUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self) -> VerifyResult:
        return VerifyResult.of(verify_entries(self.ctx.ledger.all()))


class ExportCaseUseCase:
    """按案由导出取证包。

    入选规则：`payload.caseRef` 命中，或 `subject` 在给定的 DID 集合里。
    两条都要，因为同一件事的记录分散在不同服务里 ——
    coordination 记的是工单（带 caseRef），policy 记的是吊销（带 did），
    只按一条规则筛，包就会缺半边。
    """

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_ref: str, subjects: list[str] | None = None,
                include_all: bool = False) -> Bundle:
        if not case_ref.strip() and not include_all:
            raise ValueError("导出取证包必须指定案由（case_ref）")

        wanted = {s.strip() for s in (subjects or []) if s and s.strip()}
        picked = []
        for e in self.ctx.ledger.all():
            hit_case = bool(case_ref) and e.payload.get("caseRef") == case_ref
            hit_subject = e.subject in wanted
            if include_all or hit_case or hit_subject:
                picked.append(e.to_json())

        body = {"caseRef": case_ref, "entries": picked}
        return Bundle(
            case_ref=case_ref,
            entries=picked,
            verdict=self.execute_verdict(),
            bundle_digest=digest_of(body),
            exported_at=self.ctx.clock.now(),
        )

    def execute_verdict(self) -> VerifyResult:
        return VerifyResult.of(verify_entries(self.ctx.ledger.all()))


__all__ = ["VerifyChainUseCase", "VerifyResult", "ExportCaseUseCase", "Bundle",
           "canonical"]
