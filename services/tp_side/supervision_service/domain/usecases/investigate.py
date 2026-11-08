"""协查：经 coordination 向 AP 索取归属证明。

要的是**公开材料**，不是能力：

    parentDid   父指针（AP 本地存的那份）
    phcJson     AP 手里那份 PHC 的规范化 JSON —— 用来事后复核揭露结果
    afHex       AF 的十六进制值，便于一眼比对

★ phcJson 为什么以**字符串**而不是对象传：
  coordination 的卡口只放标量（嵌套对象最容易顺手夹带密钥句柄）。
  这里不为了省事去放宽卡口 —— 放宽一次，那个卡口就再也拦不住任何东西了。

★ 拿到 PHC 之后，本服务会做一件协议里没明说但很值钱的事：
  用揭露出来的 H(ID) 复算 AF，验证"这个身份确实是这份凭证所承诺的那个"。
  见 disclose.py。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..entities import CaseState


@dataclass(frozen=True)
class InvestigateResult:
    case_id: str
    ticket_id: str
    state: str
    lineage_chain: list[str] = field(default_factory=list)


class InvestigateUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_id: str, requested_by: str) -> InvestigateResult:
        case = self.ctx.cases.get(case_id)
        if case is None:
            raise ValueError(f"案件 {case_id} 不存在")

        # ★ 铁律：未立案一律拒
        case.guard(CaseState.FILED, CaseState.INVESTIGATING)

        # 先做本地可做的那一半：上溯。这一步不惊动任何人。
        lineage = self.ctx.directory.trace(case.subject_did)
        case.lineage_chain = list(lineage.chain)

        ticket_id = self.ctx.channel.open(
            requester="TP", responder="AP", kind="lineage_proof",
            payload={"did": case.subject_did},
            case_ref=case.case_id,
        )
        case.ticket_ids = [*case.ticket_ids, ticket_id]
        if case.state is CaseState.FILED:
            case.move(CaseState.INVESTIGATING)
        self.ctx.cases.put(case)

        self.ctx.audit.append(
            kind="case.investigating", subject=case.case_id,
            payload={"caseRef": case.case_id, "subjectDid": case.subject_did,
                     "ticketId": ticket_id, "requestedBy": requested_by,
                     "lineage": list(lineage.chain)},
        )
        return InvestigateResult(case_id=case.case_id, ticket_id=ticket_id,
                                 state=case.state.value,
                                 lineage_chain=list(lineage.chain))


class CollectProofUseCase:
    """取回 AP 的答复，并把 PHC 留在案件里备用。

    单独成一个用例，是因为"发单"和"取答复"之间隔着另一个责任方的时间 ——
    把它们做成一次同步调用，等于假设 AP 一定在线，那这个系统就没法在
    AP 短暂不可用时完成追溯。
    """

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_id: str, ticket_id: str) -> dict:
        case = self.ctx.cases.get(case_id)
        if case is None:
            raise ValueError(f"案件 {case_id} 不存在")
        case.guard(CaseState.INVESTIGATING, CaseState.FILED)

        view = self.ctx.channel.get(ticket_id)
        if view.state != "answered":
            raise ValueError(
                f"工单 {ticket_id} 尚未答复（当前 {view.state}）—— 归属证明还不存在")

        answer = dict(view.answer or {})

        # ★ "已答复"不等于"给了材料"。
        #   gateway 会把"我不答应"和"我这儿没有"也回写成 answered ——
        #   因为一个明确的拒绝好过让人等 72 小时。
        #   但对岸给了拒绝，这边就不能当成取证成功往下走。
        status = str(answer.get("status") or "")
        if status == "refused":
            raise ValueError(
                f"AP 拒绝了这次协查：{answer.get('reason') or '未说明理由'}")
        if status == "not_local":
            raise ValueError(
                f"AP 表示该实例不在其节点（{answer.get('reason') or ''}）—— "
                "需向持有该实例的其他 AP 节点重新发单，本次取证不成立")
        if status and status != "ok":
            raise ValueError(f"AP 返回了未知状态 {status!r} —— 拒绝采信")

        phc_raw = answer.get("phcJson") or ""
        if not phc_raw:
            # ★ 这里原来是静默跳过：走到下面照样写一笔 case.proof_collected。
            #   账上记着"取证完成"，实际什么都没取到 —— 这是最坏的一种失败，
            #   因为它不会报错，只会在归档时变成一份空证明。
            raise ValueError(
                "AP 的答复里没有 phcJson —— 归属证明缺失，取证中止。"
                "（'已答复'不等于'给了材料'）")
        try:
            phc = json.loads(phc_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("AP 返回的 phcJson 不是合法 JSON") from exc
        parent = phc.get("parentDid") or ""
        if parent and parent not in case.lineage_chain:
            # 父指针与本地注册表不一致 —— 两边有一边在说谎，必须停下
            raise ValueError(
                f"AP 提供的父指针 {parent} 与本地上溯结果不一致，"
                "拒绝继续（需要人工比对两侧注册表）")
        case.phc_json = phc
        case.notes.append(f"phcDigest={answer.get('phcDigest', '')}")

        self.ctx.cases.put(case)
        self.ctx.audit.append(
            kind="case.proof_collected", subject=case.case_id,
            payload={"caseRef": case.case_id, "ticketId": ticket_id,
                     "parentDid": answer.get("parentDid", "")})
        return answer


__all__ = ["InvestigateUseCase", "InvestigateResult", "CollectProofUseCase"]
