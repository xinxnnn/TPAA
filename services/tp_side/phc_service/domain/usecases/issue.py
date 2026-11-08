"""phc-service 用例：G2-b / G3 签发与 D6 最终绑定。

★ 签发的三道前置，缺一不可，且都在任何密钥动作之前：
    1. 申请存在、尚未签发过（一张申请只签一次）
    2. review-service 给出双人通过的审批证据
    3. 审批证据的签名、摘要、有效期都对（check_approval，在 tp_issue 内）

TP 记录（TpRecord）里有 r_bind' / r_tp —— 原文 G3 的"本地数据库"。
它是 TP 的敏感资产：能用它把 AF 关联回 H(ID)（errata S2），只能放在 TP 域内。
"""

from __future__ import annotations

import crypto.sdk
from crypto.tpaa_v1.wire import unb64u

from services.shared.v1_http import Conflict, Forbidden, NotFound

v1 = crypto.sdk.v1


class PhcDesk:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def issue(self, *, app_id: str) -> dict:
        c = self.ctx
        if app_id in c.store.load().get("records", {}):
            raise Conflict(f"申请 {app_id} 已签发过，不能重复签发")
        approval = c.review.approval_for(app_id)                 # 未通过 → Forbidden
        opened, _ = c.identity.opened_for_issue(app_id)
        rr, rec = v1.tp.tp_issue(
            tp_hsm=c.tp_hsm, opened=opened, approval=approval, review_pk=c.review_pk,
            sup_pub=c.sup_pub, storage=c.storage, ap_ch=c.ap_ch, ap_sign_pk=c.ap_sign_pk,
            ap_enc_pk=c.ap_enc_pk, now=c.clock.now())

        def _put(d):
            if app_id in d.setdefault("records", {}):
                raise Conflict(f"申请 {app_id} 已签发过，不能重复签发")
            d["records"][app_id] = v1.records.dump(rec)
            return d

        c.store.update(_put)
        c.identity.mark(app_id, "issued")
        return {"applicationId": app_id, "rr": rr, "phcVersion": rec.phc_version}

    def finalize(self, *, app_id: str, didgr: dict) -> dict:
        c = self.ctx
        raw = c.store.load().get("records", {}).get(app_id)
        if raw is None:
            raise NotFound(f"没有 {app_id} 的签发记录")
        rec = v1.records.load(raw)
        if rec.did:
            raise Conflict("该凭证已完成 D6 最终绑定")
        final, rec2 = v1.tp.tp_finalize(
            tp_hsm=c.tp_hsm, didgr_box=didgr, rec=rec, sup_pub=c.sup_pub,
            domain1=c.domain1, now=c.clock.now(), application_id=app_id,
            tp_sign_pk=c.tp_hsm.pubkey(), ap_sign_pk=c.ap_sign_pk)

        def _put(d):
            if v1.records.load(d["records"][app_id]).did:
                raise Conflict("该凭证已完成 D6 最终绑定")
            # D4Statement 一次性消费：同一份 AP 声明不能再拿到别的申请上去 finalize。
            used = d.setdefault("d4Statements", {})
            holder = used.get(rec2.d4_record_id)
            if holder is not None and holder != app_id:
                raise Conflict(
                    f"D4 记录 {rec2.d4_record_id} 已被申请 {holder} 用过，不能跨申请复用")
            used[rec2.d4_record_id] = app_id
            d["records"][app_id] = v1.records.dump(rec2)
            return d

        c.store.update(_put)
        c.identity.mark(app_id, "finalized")
        body = {
            "version": "tpaa-v1-finalization-attestation",
            "applicationId": app_id,
            "owner": rec2.owner,
            "userSignPk": rec2.user_sign_pk,
            "did": rec2.did,
            "phcDigest": rec2.phc_digest,
            "cmi": rec2.cmi,
        }
        body["sig"] = v1.sign(c.tp_hsm, "FinalizationAttestation", v1.json_digest(body))
        return {"applicationId": app_id, "final": final, "phcVersion": rec2.phc_version,
            "attestation": body,
            "event": {"stage": "D6", "status": "finalized", "artifacts": {
                "did": rec2.did, "phcDigest": rec2.phc_digest,
                "phcVersion": rec2.phc_version, "cmi": rec2.cmi}}}

    def status(self, *, app_id: str) -> dict:
        """公开的签发/最终化状态。只给事实，不给 RR、r_bind'、r_tp、ECID。"""
        raw = self.ctx.store.load().get("records", {}).get(app_id)
        if raw is None:
            return {"applicationId": app_id, "issued": False, "finalized": False}
        rec = v1.records.load(raw)
        return {"applicationId": app_id, "issued": True, "finalized": bool(rec.did),
                "phcVersion": rec.phc_version, "phcDigest": rec.phc_digest,
                "owner": rec.owner, "did": rec.did or None,
                "d4RecordId": rec.d4_record_id or None}

    def scid_demo(self, *, app_id: str, caller: str) -> dict:
        """Decrypt only this owner's finalized CSCID in explicitly enabled demo stacks."""
        if not self.ctx.allow_demo_scid_reveal:
            raise NotFound("SCID 解密演示仅在本地 test-adapter 中启用")
        raw = self.ctx.store.load().get("records", {}).get(app_id)
        if raw is None:
            raise NotFound(f"没有 {app_id} 的签发记录")
        rec = v1.records.load(raw)
        if rec.owner != caller:
            raise Forbidden("只能查看本人凭证中的 SCID 演示结果")
        if not rec.did:
            raise Conflict("凭证尚未完成 D6，当前没有 SCID 可解密")
        try:
            encoded = rec.did.split(":")[2]
            cscid = unb64u(encoded)
            opened = self.ctx.tp_hsm.pke_open(cscid, tag="CSCID")
        except (IndexError, ValueError, TypeError) as exc:
            raise Conflict("DID 中的 SCID 格式无效，无法解密") from exc
        if not isinstance(opened, dict) or set(opened) != {"AF", "RF"}:
            raise Conflict("SCID 解密结果结构不符合 CSCID 协议")
        return {
            "applicationId": app_id,
            "did": rec.did,
            "encoding": "Base64URL(CSCID ciphertext)",
            "decryptedBy": "TP test-adapter",
            "plaintext": {"AF": opened["AF"], "RF": opened["RF"]},
            "note": "这是 CSCID 中的 AF/RF，不是用户原始身份或 H(ID)。",
        }

    def reviewer_queue(self) -> dict:
        """Reviewer read model combining masked identity and public PHC lifecycle facts."""
        applications = self.ctx.identity.review_queue()["items"]
        items = []
        for application in applications:
            lifecycle = self.status(app_id=application["applicationId"])
            items.append({
                "applicationId": application["applicationId"],
                "receivedAt": application["receivedAt"],
                "reviewState": application["state"],
                "issued": lifecycle["issued"],
                "finalized": lifecycle["finalized"],
                "phcVersion": lifecycle.get("phcVersion"),
                "phcDigest": lifecycle.get("phcDigest"),
            })
        return {"items": items}

    def did_directory(self) -> dict:
        """D6 bindings known to PHC; this is not a revocation/lineage registry."""
        records = []
        for app_id, raw in self.ctx.store.load().get("records", {}).items():
            record = v1.records.load(raw)
            if record.did:
                records.append({
                    "applicationId": app_id,
                    "did": record.did,
                    "phcVersion": record.phc_version,
                    "phcDigest": record.phc_digest,
                })
        records.sort(key=lambda item: item["applicationId"])
        return {"items": records}

    # ---- TP 域内端口：监管侧（R1 / R2）按 DID 找记录 ----
    def record_by_did(self, did: str):
        for raw in self.ctx.store.load().get("records", {}).values():
            rec = v1.records.load(raw)
            if rec.did == did:
                return rec
        raise NotFound("没有该 DID 的 TP 记录")


__all__ = ["PhcDesk"]
