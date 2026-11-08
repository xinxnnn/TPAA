"""review-service 用例：TP 单方人工审核（errata E17）。

规则：
    * 一名具备 reviewer 角色的 TP 审核员即可批准或驳回申请
    * 每份申请只能判定一次，驳回后不可逆
    * 审批证据由本服务自己的 REVIEW 域密钥签名，**本服务不持有任何协议密钥**

审核员看到的材料来自 identity-service 的掩码视图；本服务从不接触 BI / PII 原件。
"""

from __future__ import annotations

import crypto.sdk

from services.shared.v1_http import Conflict, Forbidden, NotFound

APPROVAL_TTL_HOURS = 24


class ReviewDesk:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def decide(self, *, app_id: str, reviewer: str, decision: str, note: str = "") -> dict:
        if decision not in ("approve", "reject"):
            raise ValueError("decision 只能是 approve / reject")
        if not reviewer:
            raise ValueError("缺少审核员标识")
        digest = self.ctx.identity.digest_of(app_id)        # 申请不存在时 NotFound
        now = self.ctx.clock.now()

        def _upd(d):
            rec = d.setdefault("reviews", {}).setdefault(
                app_id, {"crDigest": digest, "decisions": [], "state": "open", "approval": None})
            if rec["state"] != "open":
                label = "通过" if rec["state"] == "approved" else "驳回"
                raise Conflict(f"该申请已{label}，不再接受判定")
            if any(x["reviewer"] == reviewer for x in rec["decisions"]):
                raise Conflict("同一审核员对同一申请只能判定一次")
            rec["decisions"].append({"reviewer": reviewer, "decision": decision,
                                     "note": note, "at": now})
            if decision == "reject":
                rec["state"] = "rejected"
            else:
                approvers = [x["reviewer"] for x in rec["decisions"] if x["decision"] == "approve"]
                if approvers:
                    rec["state"] = "approved"
                    rec["approval"] = crypto.sdk.v1.tp.approve(
                        reviewer_hsm=self.ctx.review_hsm, cr_digest=digest,
                        reviewers=[approvers[0]],
                        expires=self.ctx.clock.plus_hours(APPROVAL_TTL_HOURS))
            return d

        data = self.ctx.store.update(_upd)
        rec = data["reviews"][app_id]
        self.ctx.identity.mark(app_id, rec["state"])
        self.ctx.identity.ctx.review_status[app_id] = self._view(app_id, rec)
        return self._view(app_id, rec)

    def status(self, app_id: str) -> dict:
        rec = self.ctx.store.load().get("reviews", {}).get(app_id)
        if rec is None:
            raise NotFound(f"该申请尚无审核记录：{app_id}")
        return self._view(app_id, rec)

    # ---- 进程内端口：phc-service 取审批证据 ----
    def approval_for(self, app_id: str) -> dict:
        rec = self.ctx.store.load().get("reviews", {}).get(app_id)
        if rec is None or rec["state"] != "approved":
            raise Forbidden("该申请尚未经 TP 审核通过，不得签发")
        return rec["approval"]

    @staticmethod
    def _view(app_id: str, rec: dict) -> dict:
        return {"applicationId": app_id, "state": rec["state"],
                "decisions": [{k: x[k] for k in ("reviewer", "decision", "at")}
                              for x in rec["decisions"]],
                "approved": rec["approval"] is not None}


__all__ = ["ReviewDesk"]
