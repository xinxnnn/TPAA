"""supervision-service 的 tpaa_v1 入口：举报 → 双监管员立案 → R1 联合揭露 → R2 取证。

    POST /v1/cases                         [supervisor / reviewer] 登记举报（目标 DID + 用途）
    POST /v1/cases/{id}/approve            [supervisor] 提交本人的立案签字（STAFF 私钥在本人终端签）
    POST /v1/cases/{id}/reject             [supervisor] 不予受理（必须写理由）
    POST /v1/cases/{id}/disclose           [supervisor] R1 + R2：向 AP 请求 s_ap → 还原 → 取证包封给本人
    GET  /v1/cases/{id}                    [supervisor] 案件状态（不含任何身份信息）

与 proto0（app.py）并存。复用同一个 `Case` 状态机：未立案什么都不能做。

★ 立案的"两名不同监管员"由两份**个人签名**体现，不是请求体里的两个名字。
  这两份签名原样转交 AP，AP 用自己的名录核对 —— 所以 TP 单方凑不出 AP 认可的立案。
★ 揭露结果不进库、不进响应：库里只有 H(H(ID)) 与取证包摘要；
  取证包（BI / PII）封给发起揭露的那名监管员的加密公钥，只有他的终端解得开。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field

from fastapi import Body, FastAPI, HTTPException, Response

import crypto.sdk
from services.shared.store import JsonStore
from services.shared.v1_http import Conflict, Forbidden, NotFound, SystemClock, install_errors

from .domain.entities import Case, CaseError, CaseState, IllegalCaseTransition, NotFiled

v1 = crypto.sdk.v1
ASSIST_TTL_HOURS = 1


@dataclass
class SupervisionV1Context:
    tp_hsm: object
    sup_key: object              # 监管 Paillier 私钥（全系统唯一能解 RF / ECID 的那把）
    records: object              # phc-service 端口：record_by_did(did) -> TpRecord
    storage: object              # IPFS
    ap_assist: object            # callable(req: dict) -> sealed answer box（跨域，HTTP）
    staff: dict                  # signPkHex → {"id", "role", "encPub"?}
    store: JsonStore
    clock: object = field(default_factory=SystemClock)
    legacy_dids: set[str] = field(default_factory=set)
    forensic_open: object | None = None

    def staff_by_id(self, sid: str) -> tuple[str, dict]:
        for pk, m in self.staff.items():
            if m["id"] == sid:
                return pk, m
        raise Forbidden(f"人员名录里没有 {sid}")


class SupervisionV1Desk:
    def __init__(self, ctx: SupervisionV1Context) -> None:
        self.ctx = ctx

    # ---- 案件存取 ----
    def _load(self, case_id: str) -> tuple[Case, dict]:
        raw = self.ctx.store.load().get("cases", {}).get(case_id)
        if raw is None:
            raise NotFound(f"案件不存在：{case_id}")
        return Case.from_json(raw["case"]), raw

    def _save(self, case: Case, extra: dict) -> None:
        def _put(d):
            d.setdefault("cases", {})[case.case_id] = {**extra, "case": case.to_json()}
            return d
        self.ctx.store.update(_put)

    @staticmethod
    def _guard(case: Case, *allowed: CaseState) -> None:
        try:
            case.guard(*allowed)
        except NotFiled as exc:
            raise Forbidden(str(exc)) from exc
        except IllegalCaseTransition as exc:
            raise Conflict(str(exc)) from exc

    # ---- 举报 ----
    def report(self, *, did: str, purpose: str, allegation: str, evidence_ref: str,
               reporter: str) -> dict:
        if not purpose.strip():
            raise ValueError("必须写明协查用途 —— 它会进入立案签字与 AP 的审计")
        if did in self.ctx.legacy_dids:
            raise Conflict("该 DID 由旧版本地演示环境签发，无法在当前环境完成 R1/R2 追溯")
        v1.tp.tp_open_did(tp_hsm=self.ctx.tp_hsm, did=did)          # 只验格式与可解，不留结果
        self.ctx.records.record_by_did(did)
        case = Case(case_id="case-" + secrets.token_hex(8), subject_did=did, reporter=reporter,
                    evidence_ref=evidence_ref, allegation=allegation,
                    reported_at=self.ctx.clock.now())
        self._save(case, {"purpose": purpose, "approvals": []})
        return self.view(case.case_id)

    # ---- 立案：两名不同监管员的个人签字 ----
    def approve(self, case_id: str, *, approval: dict, caller: str) -> dict:
        case, raw = self._load(case_id)
        if case.state is not CaseState.REPORTED:
            raise Conflict(f"案件当前为 {case.state.value}，不再接受立案签字")
        pk, member = self.ctx.staff_by_id(caller)
        if approval.get("signPk") != pk:
            raise Forbidden("立案签字的公钥不是登录监管员本人的")
        v1.case.check_case_approval(approval, case_id=case_id, did=case.subject_did,
                                    purpose=raw["purpose"])
        if any(a["signPk"] == pk for a in raw["approvals"]):
            raise Conflict("同一监管员不能签两次")
        raw["approvals"].append(approval)
        signers = [self.ctx.staff[a["signPk"]]["id"] for a in raw["approvals"]]
        if len(signers) >= v1.case.MIN_APPROVERS:
            try:
                case.file(reviewers=signers, note="两名监管员签字", at=self.ctx.clock.now())
            except CaseError as exc:
                raise Conflict(str(exc)) from exc
        self._save(case, raw)
        return self.view(case_id)

    def reject(self, case_id: str, *, note: str, caller: str) -> dict:
        case, raw = self._load(case_id)
        if case.state is not CaseState.REPORTED:
            raise Conflict(f"案件当前为 {case.state.value}，不能再驳回")
        if not note.strip():
            raise ValueError("不予受理必须写明理由")
        case.reject(note=f"{caller}: {note}")
        self._save(case, raw)
        return self.view(case_id)

    # ---- R1 + R2 ----
    def disclose(self, case_id: str, *, caller: str) -> dict:
        c = self.ctx
        case, raw = self._load(case_id)
        # INVESTIGATING 也允许：上一次跨域请求失败（AP 拒绝 / 网络断）时可以重试
        self._guard(case, CaseState.FILED, CaseState.INVESTIGATING)
        _, member = c.staff_by_id(caller)
        if not member.get("encPub"):
            raise Forbidden("该监管员没有登记加密公钥，取证包无处可封")

        af, rf = v1.tp.tp_open_did(tp_hsm=c.tp_hsm, did=case.subject_did)
        rec = c.records.record_by_did(case.subject_did)
        rid = "assist-" + secrets.token_hex(8)
        req = v1.case.build_assist_request(
            c.tp_hsm, request_id=rid, case_id=case_id, did=case.subject_did, af=af,
            purpose=raw["purpose"], approvals=raw["approvals"],
            expires=c.clock.plus_hours(ASSIST_TTL_HOURS))
        if case.state is CaseState.FILED:
            case.move(CaseState.INVESTIGATING)
        case.ticket_ids.append(rid)
        self._save(case, raw)

        s_ap = v1.case.tp_open_answer(c.tp_hsm, c.ap_assist(req), request_id=rid)   # R1 跨域
        hid = v1.tp.tp_reveal(sup_key=c.sup_key, rf=rf, s_ap=s_ap, rec=rec)
        bundle = v1.tp.tp_recover_pii(tp_hsm=c.tp_hsm, sup_key=c.sup_key, rec=rec, rf=rf,
                                      storage=c.storage)                              # R2
        box = v1.case.seal_forensic(recipient_enc_pk=int(member["encPub"], 16),
                                    case_id=case_id, bundle={"did": case.subject_did, **bundle})

        now = c.clock.now()
        case.disclosed_hash = hashlib.sha256(format(hid, "x").encode()).hexdigest()
        case.disclosed_at = now
        case.move(CaseState.DISCLOSED)
        case.forensic_digest = hashlib.sha256(
            json.dumps(box, sort_keys=True).encode()).hexdigest()
        case.forensic_box = box
        raw["forensicRecipient"] = caller
        case.sealed_at = now
        case.move(CaseState.SEALED)
        self._save(case, raw)
        return {"caseId": case_id, "state": case.state.value, "forensic": box,
                "forensicDigest": case.forensic_digest}

    def view(self, case_id: str) -> dict:
        case, raw = self._load(case_id)
        j = case.to_json()
        approvers = [
            self.ctx.staff[approval["signPk"]]["id"]
            for approval in raw["approvals"]
            if approval["signPk"] in self.ctx.staff
        ]
        return {"caseId": case_id, "state": j["state"], "subjectDid": case.subject_did,
                "reporter": case.reporter, "allegation": case.allegation,
                "evidenceRef": case.evidence_ref, "reportedAt": case.reported_at,
                "filedAt": case.filed_at, "purpose": raw["purpose"],
                "approvers": approvers, "approvalCount": len(raw["approvals"]),
                "forensicDigest": j["forensicDigest"], "sealedAt": j["sealedAt"]}

    def list_cases(self) -> list[dict]:
        cases = self.ctx.store.load().get("cases", {})
        ordered = sorted(
            cases.items(),
            key=lambda item: item[1].get("case", {}).get("reportedAt", ""),
            reverse=True)
        return [self.view(case_id) for case_id, _ in ordered]

    def trace_targets(self) -> dict:
        items = self.ctx.records.did_directory()["items"]
        eligible = [item for item in items if item["did"] not in self.ctx.legacy_dids]
        return {"items": eligible, "excludedLegacyCount": len(items) - len(eligible)}

    def forensic(self, case_id: str, *, caller: str) -> dict:
        case, raw = self._load(case_id)
        if case.state is not CaseState.SEALED or not case.forensic_box:
            raise Conflict("该案件尚无已封存取证包")
        if raw.get("forensicRecipient") != caller:
            raise Forbidden("取证包仅可由生成时指定的监管员查看")
        return {"caseId": case_id, "forensic": case.forensic_box,
                "forensicDigest": case.forensic_digest}

    def identity_info(self, case_id: str, *, caller: str) -> dict:
        case, raw = self._load(case_id)
        if case.state is not CaseState.SEALED or not case.forensic_box:
            raise Conflict("案件尚未完成双人立案、AP 协查和取证封存")
        if raw.get("forensicRecipient") != caller:
            raise Forbidden("身份信息仅可由本案指定的监管员调阅")
        if self.ctx.forensic_open is None:
            raise HTTPException(status_code=503, detail="监管员取证包解密能力未配置")
        expected_digest = hashlib.sha256(
            json.dumps(case.forensic_box, sort_keys=True).encode()).hexdigest()
        if expected_digest != case.forensic_digest:
            raise Conflict("取证包摘要校验失败，拒绝解封身份信息")

        payload = self.ctx.forensic_open(caller, case.forensic_box)
        if not isinstance(payload, dict):
            raise Conflict("取证包解封结果格式无效")
        if payload.get("caseId") != case_id or payload.get("did") != case.subject_did:
            raise Conflict("取证包案件或 DID 与当前案件不匹配")
        pii = payload.get("PII")
        bi = payload.get("BI")
        if (not isinstance(pii, dict)
                or not all(isinstance(key, str) and isinstance(value, str)
                           for key, value in pii.items())
                or not isinstance(bi, dict)
                or not all(isinstance(key, str) for key in bi)):
            raise Conflict("取证包中的身份材料格式无效")

        accessed_at = self.ctx.clock.now()

        def _audit(data):
            entry = data.setdefault("cases", {}).get(case_id)
            if entry is None:
                raise NotFound(f"案件不存在：{case_id}")
            entry.setdefault("identityAccesses", []).append({
                "by": caller, "at": accessed_at,
            })
            return data

        self.ctx.store.update(_audit)
        return {
            "caseId": case_id,
            "did": case.subject_did,
            "identityVerified": True,
            "pii": pii,
            "biFields": sorted(bi),
            "purpose": raw["purpose"],
            "accessedBy": caller,
            "accessedAt": accessed_at,
            "forensicDigest": case.forensic_digest,
        }


def build_context(*, tp_hsm, sup_key, records, storage, ap_assist, staff: dict, db_path: str,
                  clock=None, legacy_dids: set[str] | None = None,
                  forensic_open=None) -> SupervisionV1Context:
    if getattr(tp_hsm, "domain", None) != "TP":
        raise RuntimeError("supervision-service 需要 TP 域的 HSM")
    if not sup_key.private_key_present():
        raise RuntimeError("supervision-service 需要完整的监管密钥（只有它能解 RF / ECID）")
    return SupervisionV1Context(tp_hsm=tp_hsm, sup_key=sup_key, records=records,
                                storage=storage, ap_assist=ap_assist, staff=staff,
                                store=JsonStore(db_path), clock=clock or SystemClock(),
                                legacy_dids=set(legacy_dids or ()),
                                forensic_open=forensic_open)


def create_app(*, ctx: SupervisionV1Context, verifier) -> FastAPI:
    app = FastAPI(title="supervision-service (tpaa_v1)", version="1.0.0")
    app.state.domain = "tp-side"
    app.state.ctx = ctx
    app.state.desk = desk = SupervisionV1Desk(ctx)
    install_errors(app)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "supervision-service", "profile": "tpaa_v1"}

    @app.post("/v1/cases")
    def report(did: str = Body(...), purpose: str = Body(...), allegation: str = Body(""),
               evidenceRef: str = Body(""),
               who: dict = verifier.require("supervisor", "reviewer")):
        return desk.report(did=did, purpose=purpose, allegation=allegation,
                           evidence_ref=evidenceRef, reporter=who["sub"])

    @app.post("/v1/cases/{case_id}/approve")
    def approve(case_id: str, approval: dict = Body(..., embed=True),
                who: dict = verifier.require("supervisor")):
        return desk.approve(case_id, approval=approval, caller=who["sub"])

    @app.post("/v1/cases/{case_id}/reject")
    def reject(case_id: str, note: str = Body(..., embed=True),
               who: dict = verifier.require("supervisor")):
        return desk.reject(case_id, note=note, caller=who["sub"])

    @app.post("/v1/cases/{case_id}/disclose")
    def disclose(case_id: str, who: dict = verifier.require("supervisor")):
        return desk.disclose(case_id, caller=who["sub"])

    @app.get("/v1/cases/{case_id}")
    def view(case_id: str, _: dict = verifier.require("supervisor")):
        return desk.view(case_id)

    @app.get("/v1/cases")
    def list_cases(_: dict = verifier.require("supervisor", "reviewer")):
        return {"items": desk.list_cases()}

    @app.get("/v1/targets")
    def trace_targets(_: dict = verifier.require("supervisor", "reviewer")):
        return desk.trace_targets()

    @app.get("/v1/cases/{case_id}/forensic")
    def forensic(case_id: str, who: dict = verifier.require("supervisor")):
        return desk.forensic(case_id, caller=who["sub"])

    @app.get("/v1/cases/{case_id}/identity")
    def identity_info(case_id: str, response: Response,
                      who: dict = verifier.require("supervisor")):
        response.headers["Cache-Control"] = "no-store"
        return desk.identity_info(case_id, caller=who["sub"])

    return app


__all__ = ["SupervisionV1Context", "SupervisionV1Desk", "build_context", "create_app"]
