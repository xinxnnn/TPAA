"""揭露（R1）：把 CSCID 打开，得到 H(ID)。

这是全系统唯一一处"密文变成身份"的地方。三条纪律：

1. **未立案不得进入**（`case.guard`）。
2. **明文只经手一次，不落库**。案件里只存 H(ID) 的摘要 ——
   因为案件库会被备份、会被运维打开、会被导出做统计。
   一个"库里躺着所有被调查者身份"的库，本身就是下一桩案子。
3. **打开之后要自证**：拿还原出的 H(ID) 去复算 PHC 里的 AF。
   复算不成立，说明这份 CSCID 被人换过、或者这个 DID 压根不属于这个人。
   不做这一步的揭露，等于"把解密结果当成事实"。

第 3 条依赖 AP 在协查里回传的那份 PHC。没有 PHC 时仍然允许揭露，
但会在结果里标 `verified=False` —— 让人看得见"这次没验"，
而不是让它悄悄通过。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import crypto.sdk

from ..entities import CaseState


@dataclass(frozen=True)
class DiscloseResult:
    case_id: str
    subject_did: str
    identity_hash: str            # 十六进制明文，**只出现在这一次响应里**
    identity_digest: str
    state: str
    verified: bool                # AF 复算是否成立
    verify_note: str = ""


class DiscloseUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, case_id: str, requested_by: str) -> DiscloseResult:
        case = self.ctx.cases.get(case_id)
        if case is None:
            raise ValueError(f"案件 {case_id} 不存在")

        # ★ 铁律
        case.guard(CaseState.FILED, CaseState.INVESTIGATING, CaseState.DISCLOSED)

        cscid = self.ctx.directory.reveal_cscid(
            case.subject_did, case_ref=case.case_id, requested_by=requested_by)

        hid = crypto.sdk.open_identity(int(cscid), self.ctx.key)
        hid_hex = f"{hid:064x}"

        verified, note = self._verify_against_phc(case, hid)

        digest = hashlib.sha256(hid_hex.encode()).hexdigest()
        case.disclosed_hash = digest
        case.disclosed_at = self.ctx.clock.now()
        if case.state is not CaseState.DISCLOSED:
            case.move(CaseState.DISCLOSED)
        self.ctx.cases.put(case)

        # 审计里只放摘要 —— 审计链会被导出给第三方
        self.ctx.audit.append(
            kind="case.disclosed", subject=case.case_id,
            payload={"caseRef": case.case_id, "subjectDid": case.subject_did,
                     "identityDigest": digest, "verified": verified,
                     "requestedBy": requested_by},
        )
        return DiscloseResult(
            case_id=case.case_id, subject_did=case.subject_did,
            identity_hash=hid_hex, identity_digest=digest,
            state=case.state.value, verified=verified, verify_note=note)

    # ------------------------------------------------------------------

    def _verify_against_phc(self, case, hid: int) -> tuple[bool, str]:
        """用 H(ID) 复算 AF。成立即证明"这个身份确实是这份凭证承诺的那个"。"""
        phc = case.phc_json
        if not phc:
            return False, "未取得 PHC（协查未回传），本次揭露未经 AF 复核"
        tp_ch = getattr(self.ctx, "tp_ch", None)
        if tp_ch is None:
            return False, "未注入 TP 公钥句柄，无法复核 AF"

        try:
            obj = crypto.sdk.phc_json_to_obj(phc)
            msg = obj.af_message(hid, int(self.ctx.policy.get("tau", 1)),
                                 int(self.ctx.policy.get("crf", 1)))
            ok = tp_ch.compute(msg, obj.tpm_af_r) == obj.tpm_af
        except Exception as exc:                     # noqa: BLE001
            return False, f"AF 复核时出错：{exc}"

        if not ok:
            return False, (
                "AF 复核不成立 —— 还原出的身份与凭证承诺的不一致，"
                "可能是 CSCID 被封存后被调换，必须人工介入")
        return True, "AF 复核通过：身份与凭证一致"


__all__ = ["DiscloseUseCase", "DiscloseResult"]
