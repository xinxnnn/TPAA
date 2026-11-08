"""受控揭示 CSCID（给监管立案后用）。

★ 这个用例的边界必须说清楚，否则它会被当成一个后门：

    **它不判断案子立没立。**
    立案状态只有 supervision-service 知道，号码簿不该去问 ——
    一旦它开始理解"什么是立案"，它就得跟着案由规则一起改版，
    而号码簿是全系统最不该频繁改的东西。

    它做的是**留痕**：谁、为了哪个案由、在什么时候取走了哪一条密文。
    真正的闸门在 supervision 的用例里（未立案直接抛），
    而"只有 TP 区内网能调"由部署保证（mTLS + 网络策略）。

    换句话说：这里防的是"事后说不清"，不是"事前拿不到"。
    把两件事混在一起，往往两件都做不好。

★ 取走的是**密文**。CSCID 本身打不开 —— 打开它需要监管域里的那把密钥，
  而那把密钥从不进入本服务。所以即使这个端点被滥用，
  攻击者拿到的也只是一串无法还原的密文。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import UnknownDid


@dataclass(frozen=True)
class RevealCommand:
    did: str
    case_ref: str
    requested_by: str


@dataclass(frozen=True)
class RevealResult:
    did: str
    cscid: str
    case_ref: str


class RevealCscidUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, cmd: RevealCommand) -> RevealResult:
        if not cmd.case_ref.strip():
            raise ValueError("取走 CSCID 必须写明案由 —— 无案由的取用不可审计")
        if not cmd.requested_by.strip():
            raise ValueError("取走 CSCID 必须记录取用人")

        rec = self.ctx.registry.get(cmd.did)
        if rec is None:
            raise UnknownDid(f"{cmd.did} 未登记")
        if not rec.cscid:
            raise UnknownDid(f"{cmd.did} 没有封存的 CSCID —— 当时未封存，无从揭示")

        # 留痕先于返还：先记账，再给东西。
        # 顺序反过来的话，进程在两步之间被杀掉，就出现了一次"无记录的取用"。
        self.ctx.registry.log_access(
            did=cmd.did, case_ref=cmd.case_ref, requested_by=cmd.requested_by,
            at=self.ctx.clock.now())

        return RevealResult(did=cmd.did, cscid=rec.cscid, case_ref=cmd.case_ref)


__all__ = ["RevealCommand", "RevealResult", "RevealCscidUseCase"]
