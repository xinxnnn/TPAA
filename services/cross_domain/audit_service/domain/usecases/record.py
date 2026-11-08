"""往审计链里追加一条。

追加这件事本身很朴素，但有三条纪律：

1. **seq 与 prev_hash 由账本给，不由调用方给**。
   让调用方传这两个值，等于让写日志的人自己决定链怎么接 —— 那就不叫链了。
2. **附加信息里不许放密钥**。审计链会被导出、被第三方复算、被贴进取证包，
   它天然是"最不该有秘密的地方"。
3. **子体 PHC 存证必须带哈希**。只存一份 JSON，事后无法证明它没被换过；
   只存一个哈希，事后又还原不出原文。两个都要。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import AuditEntry, digest_of


@dataclass(frozen=True)
class RecordResult:
    entry_id: str
    seq: int
    hash: str


# 与 coordination 的卡口同源：审计链对"密钥形态"零容忍
_FORBIDDEN_KEYS = {"sk", "privatekey", "private_key", "trapdoor", "secret",
                   "schnorr_sk", "chameleon_sk"}


class RecordUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, kind: str, subject: str,
                payload: dict | None = None) -> RecordResult:
        if not kind.strip():
            raise ValueError("审计条目必须写明 kind")
        if not subject.strip():
            raise ValueError("审计条目必须写明 subject（谁/哪一条）")

        body = dict(payload or {})
        for k in body:
            if str(k).strip().lower().replace("-", "").replace("_", "") in _FORBIDDEN_KEYS:
                raise ValueError(f"审计载荷不得包含 {k!r} —— 审计链会被导出给第三方")

        entry = self.ctx.ledger.append(
            at=self.ctx.clock.now(), kind=kind, subject=subject, payload=body)
        return RecordResult(entry_id=entry.entry_id, seq=entry.seq, hash=entry.hash)


class AttestPhcUseCase:
    """子体 PHC 存证（§9.3 的硬要求）。

    ★ 为什么子体必须存证、主智能体反而可以宽松一些：
      子体任务结束就可能被销毁，而它恰恰是最容易被拿去作恶的那一个
      （临时、短命、可批量派生）。凭证若不留痕，追溯在子体这一层就断，
      剩下的只有一句"它已经不在了"。
    """

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, did: str, phc_json: dict,
                parent_did: str = "") -> RecordResult:
        if self.ctx.attest is None:
            raise RuntimeError(
                "未配置子体 PHC 存证去处 —— 拒绝在无存证的情况下继续派生"
                "（这是 §9.3 的硬要求，不是可选项）")
        if not did.strip():
            raise ValueError("存证必须指明 DID")

        att_id = self.ctx.attest.put(did=did, phc_json=phc_json)
        entry = self.ctx.ledger.append(
            at=self.ctx.clock.now(), kind="phc.attested", subject=did,
            payload={"did": did, "parentDid": parent_did,
                     "phcHash": digest_of(phc_json), "attachment": att_id})
        return RecordResult(entry_id=entry.entry_id, seq=entry.seq, hash=entry.hash)


__all__ = ["RecordUseCase", "RecordResult", "AttestPhcUseCase", "AuditEntry"]
