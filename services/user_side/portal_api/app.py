"""Authenticated user-zone orchestration for the tpaa_v1 credential flow."""

from __future__ import annotations

import base64
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

import crypto.sdk
from services.shared.store import JsonStore
from services.shared.v1_auth import AuthIssuer, install_auth_routes
from services.shared.v1_http import Forbidden, LazyApp, NotFound, SystemClock, install_errors
from services.user_side.portal_api.local_browser_session import (
    COOKIE_NAME, LocalBrowserSessions, require_session, same_origin,
)

v1 = crypto.sdk.v1
EC_G, EC_Q, EC_P = v1.EC_G, v1.EC_Q, v1.EC_P
DL_G, DL_Q, DL_P = v1.DL_G, v1.DL_Q, v1.DL_P
ser_point, in_subgroup = v1.ser_point, v1.in_subgroup


@dataclass
class DomainPort:
    get_fn: Callable[[str], dict]
    post_fn: Callable[[str, dict, str], dict]

    def get(self, path: str) -> dict:
        return self.get_fn(path)

    def post(self, path: str, body: dict, owner: str) -> dict:
        return self.post_fn(path, body, owner)


class ProtocolExecutor(Protocol):
    def custody_profile(self) -> str: ...
    """User-controlled protocol execution boundary; never implemented by PortalDesk."""

    def public_signing_key(self) -> str: ...
    def application_id(self, label: str) -> str | None: ...
    def set_application(self, label: str, app_id: str) -> None: ...
    def build_cr(self, **kwargs) -> dict: ...
    def accept_rr(self, label: str, rr: dict, *, owner: str, application_id: str) -> dict: ...
    def accept_g4(self, label: str, *, owner: str, application_id: str) -> dict: ...
    def build_ar(self, label: str, *, expires: str, owner: str, application_id: str) -> dict: ...
    def open_cmm(self, label: str, cmm_box: dict, *, owner: str, application_id: str) -> dict: ...
    def build_paci(self, label: str, *, selection: list[dict], owner: str, application_id: str) -> dict: ...
    def accept_par(self, label: str, par: dict, *, owner: str, application_id: str) -> dict: ...
    def build_didgr(self, label: str, *, expires: str, owner: str, application_id: str) -> dict: ...
    def verify_final(self, label: str, final: dict, finalization_attestation: dict,
                     *, owner: str, application_id: str) -> dict: ...
    def accept_final(self, label: str, *, owner: str, application_id: str) -> dict: ...
    def publication_receipt(self, label: str, *, owner: str, application_id: str) -> dict: ...
    def credential(self, label: str, *, owner: str, application_id: str) -> dict: ...
    def pending_request(self, label: str, *, owner: str) -> dict: ...
    def events(self, label: str, *, owner: str, application_id: str | None = None) -> list[dict]: ...


@dataclass
class PortalContext:
    wallet_root: Path
    store: JsonStore
    tp: DomainPort
    ap: DomainPort
    phc: DomainPort
    agent: DomainPort
    auth: AuthIssuer
    clock: object = None
    handlers: dict[str, ProtocolExecutor] | None = None
    execution_profile: str = "test-adapter"

    def __post_init__(self) -> None:
        if self.execution_profile not in {"test-adapter", "test-adapter-http", "user-controlled", "production"}:
            raise ValueError("未知的用户执行器 profile")
        if self.clock is None:
            self.clock = SystemClock()
        if self.handlers is None:
            self.handlers = {}


class PortalDesk:
    def __init__(self, ctx: PortalContext) -> None:
        self.ctx = ctx

    def _executor(self, owner: str) -> ProtocolExecutor:
        if self.ctx.execution_profile == "production":
            raise Forbidden("production profile 尚未配置用户独立控钥钱包，拒绝代签")
        if owner not in self.ctx.handlers:
            raise RuntimeError("当前部署未配置独立的用户端协议执行器")
        executor = self.ctx.handlers[owner]
        if self.ctx.execution_profile == "user-controlled":
            profile = getattr(executor, "custody_profile", lambda: "test-adapter")()
            if profile != "user-controlled":
                raise Forbidden("当前用户执行器不能证明独立控钥，拒绝 user-controlled 流程")
        return executor

    def _signing_key(self, owner: str) -> str:
        executor = self._executor(owner)
        key = executor.public_signing_key()
        if v1.owner_of(v1.pk_from_hex(key)) != owner:
            raise Forbidden("执行器公钥与当前用户归属不符")
        return key

    def login_body(self, owner: str, challenge: dict) -> dict:
        executor = self._executor(owner)
        key = self._signing_key(owner)
        body = executor.login_body(challenge)
        if body.get("signPk") != key or body.get("challenge") != challenge.get("challenge"):
            raise Forbidden("执行器登录响应与挑战或用户公钥不一致")
        return body

    def _row(self, owner: str, app_id: str) -> dict:
        row = self.ctx.store.load().get("applications", {}).get(app_id)
        if row is None:
            raise NotFound(f"申请不存在：{app_id}")
        if row["owner"] != owner:
            raise Forbidden("只能访问自己的申请")
        return row

    def initialize(self, owner: str) -> dict:
        tp_keys = self.ctx.tp.get("/v1/keys")
        ap_keys = self.ctx.agent.get("/v1/tpaa/keys")
        supervision = self.ctx.phc.get("/v1/phc/keys")
        paillier = supervision["paillier"]
        g1 = int(paillier["g1"], 16)
        n = int(paillier["n"], 16)
        return {"profile": v1.PROFILE, "owner": owner,
                "userSignPk": self._signing_key(owner),
                "paramsId": v1.initialization.PARAMS_ID,
                "publicParameters": {
                    "profile": v1.PROFILE,
                    "paramsId": v1.initialization.PARAMS_ID,
                    "dl": {"p": format(DL_P, "x"), "q": format(DL_Q, "x"),
                           "g": format(DL_G, "x"), "pBits": DL_P.bit_length(),
                           "qBits": DL_Q.bit_length()},
                    "ellipticCurve": {"name": "secp256k1",
                                      "fieldP": format(EC_P, "x"),
                                      "orderQ": format(EC_Q, "x"),
                                      "generatorG": ser_point(EC_G).hex()},
                    "paillier": {**paillier, "nBits": n.bit_length(),
                                 "purpose": supervision["purpose"]},
                },
                "publicKeys": {
                    "user": {"pk": self._signing_key(owner)},
                    "ap": ap_keys,
                    "tp": {"pk": tp_keys["signPk"], "cpk": tp_keys["chameleonCpk"],
                           "encPub": tp_keys["encPub"]},
                },
                "checks": {"userExecutorLoaded": True, "protocolProfile": "ready",
                           "dlGeneratorInSubgroup": in_subgroup(DL_G),
                           "paillierGeneratorMatchesModulus": g1 == n + 1,
                           "tpPublicKeyLoaded": bool(tp_keys.get("signPk") and
                                                     tp_keys.get("encPub") and
                                                     tp_keys.get("chameleonCpk")),
                           "apPublicKeyLoaded": bool(ap_keys.get("signPk") and
                                                     ap_keys.get("encPub") and
                                                     ap_keys.get("chameleonCpk")),
                           "publicOnly": True,
                           "executionProfile": self.ctx.execution_profile,
                           "userControlledExecution": self.ctx.execution_profile == "user-controlled"}}

    def list_applications(self, owner: str) -> dict:
        """只返回当前用户的公开索引；不读取 executor 状态或身份材料。"""
        rows = self.ctx.store.load().get("applications", {}).values()
        items = []
        for row in rows:
            if row.get("owner") != owner:
                continue
            pub = next((e for e in row.get("events", []) if e.get("stage") == "PUB"), None)
            final = next((e for e in row.get("events", [])
                          if e.get("stage") == "FINAL" and e.get("status") == "user_accepted"), None)
            items.append({"applicationId": row["applicationId"], "state": row["state"],
                          "createdAt": row.get("createdAt"),
                          "did": (final or {}).get("artifacts", {}).get("did"),
                          "digest": (pub or {}).get("artifacts", {}).get("buildDigest")})
        items.sort(key=lambda item: item.get("createdAt") or "", reverse=True)
        return {"items": items}

    def create_application(self, owner: str, body: dict) -> dict:
        if self.ctx.execution_profile == "user-controlled":
            return self._create_prepared_application(owner, body)
        if not isinstance(body.get("pii"), dict) or not body["pii"].get("ID"):
            raise ValueError("身份申请需要 ID 字段")
        if not isinstance(body.get("bi"), dict):
            raise ValueError("BI 必须是对象")
        photo = body["bi"].get("facePhoto")
        if photo is not None:
            self._validate_face_photo(photo)
        executor = self._executor(owner)
        sign_pk = self._signing_key(owner)
        initialization = self.initialize(owner)
        public_keys = initialization["publicKeys"]
        tp_keys = {"signPk": public_keys["tp"]["pk"],
                   "chameleonCpk": public_keys["tp"]["cpk"],
                   "encPub": public_keys["tp"]["encPub"]}
        ap_keys = public_keys["ap"]
        tp_slot = self.ctx.tp.post("/v1/slots", {"userSignPk": sign_pk}, owner)
        ap_slot = self.ctx.agent.post("/v1/tpaa/slots", {"userSignPk": sign_pk}, owner)
        label = "flow-" + secrets.token_hex(10)
        cr = executor.build_cr(label=label, owner=owner, pii=body["pii"], bi=body["bi"],
                               tp_keys=tp_keys, ap_keys=ap_keys, tp_slot=tp_slot,
                               ap_slot=ap_slot, expires=self.ctx.clock.plus_hours(1))
        accepted = self.ctx.tp.post("/v1/applications", {"cr": cr}, owner)
        app_id = accepted["applicationId"]
        executor.set_application(label, app_id, owner=owner)
        row = {"applicationId": app_id, "owner": owner, "executorLabel": label,
               "createdAt": self.ctx.clock.now(), "state": "pending_review", "events": [
                   {"stage": "INIT", "status": "complete", "at": self.ctx.clock.now(),
                    "artifacts": initialization},
                   {"stage": "G1", "status": "accepted_by_tp", "at": self.ctx.clock.now(),
                    "artifacts": {"applicationId": app_id, "crDigest": accepted["crDigest"],
                                  "requestId": executor.pending_request(label, owner=owner)["requestId"],
                                  "recipient": "TP identity-service",
                                  "encryptedCRAccepted": True,
                                  "crEnvelope": cr,
                                  "submittedPIIFields": sorted(body["pii"]),
                                  "submittedBIFields": sorted(body["bi"])}},
                   {"stage": "REVIEW", "status": "pending", "artifacts": {}}]}
        self.ctx.store.update(lambda d: d.setdefault("applications", {}).__setitem__(app_id, row) or d)
        return self.timeline(owner, app_id)

    def _create_prepared_application(self, owner: str, body: dict) -> dict:
        """Relay an already sealed CR; Portal never receives PII/BI in this mode.

        A user-controlled wallet must create the CR and retain its pending state.
        The wallet's own interface must require user presence for later signing.
        """
        if not isinstance(body, dict) or set(body) != {"cr", "walletLabel", "requestId"}:
            raise ValueError("user-controlled 申请只接受 cr、walletLabel、requestId")
        cr, label, request_id = body["cr"], body["walletLabel"], body["requestId"]
        if not isinstance(cr, dict) or not isinstance(label, str) or not label or \
                not isinstance(request_id, str) or not request_id:
            raise ValueError("预构造 CR、钱包标签或请求号无效")
        executor = self._executor(owner)
        pending = executor.pending_request(label, owner=owner)
        if pending.get("requestId") != request_id or pending.get("sealedCrDigest") != v1.json_digest(cr):
            raise Forbidden("提交的 CR 与用户钱包保留的待处理请求不一致")
        initialization = self.initialize(owner)
        accepted = self.ctx.tp.post("/v1/applications", {"cr": cr}, owner)
        app_id = accepted["applicationId"]
        executor.set_application(label, app_id, owner=owner)
        now = self.ctx.clock.now()
        row = {"applicationId": app_id, "owner": owner, "executorLabel": label,
               "createdAt": now, "state": "pending_review", "events": [
                   {"stage": "INIT", "status": "complete", "at": now,
                    "artifacts": initialization},
                   {"stage": "G1", "status": "accepted_by_tp", "at": now,
                    "artifacts": {"applicationId": app_id, "crDigest": accepted["crDigest"],
                                  "requestId": request_id, "recipient": "TP identity-service",
                                  "encryptedCRAccepted": True, "crEnvelope": cr}},
                   {"stage": "REVIEW", "status": "pending", "artifacts": {}}]}
        self.ctx.store.update(lambda d: d.setdefault("applications", {}).__setitem__(app_id, row) or d)
        return self.timeline(owner, app_id)

    @staticmethod
    def _validate_face_photo(value: object) -> None:
        match = re.fullmatch(r"data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})", value) \
            if isinstance(value, str) else None
        if match is None:
            raise ValueError("人脸照片必须是 JPEG、PNG 或 WebP 的 Base64 data URL")
        try:
            image = base64.b64decode(match.group(2), validate=True)
        except ValueError as exc:
            raise ValueError("人脸照片编码无效") from exc
        if not image or len(image) > 64 * 1024:
            raise ValueError("人脸照片不能为空且不得超过 64 KiB")
        kind = match.group(1)
        valid = (
            kind == "jpeg" and image.startswith(b"\xff\xd8\xff")
            or kind == "png" and image.startswith(b"\x89PNG\r\n\x1a\n")
            or kind == "webp" and len(image) >= 12 and image[:4] == b"RIFF" and image[8:12] == b"WEBP"
        )
        if not valid:
            raise ValueError("人脸照片内容与声明的图片格式不匹配")

    _STAGE_ORDER = {"INIT": 0, "G1": 1, "REVIEW": 2, "G3": 3, "G4": 4, "D1": 5,
                    "D2": 6, "D3": 7, "D4": 8, "D5": 9, "D6": 10, "FINAL": 11, "PUB": 12, "RUN": 13}

    def _merge_review(self, row: dict) -> dict:
        """把 TP 的 REVIEW 事件并进一份**副本**，不落盘。

        ★ GET 不写库：以前 timeline() 每次读都 _save，审核事件被反复重写，
          而且一次纯展示请求会改状态机。判据以持久的 row["state"] 为准，
          events 只是展示。
        """
        merged = dict(row)
        merged["events"] = list(row["events"])
        review = self.ctx.tp.get(f"/v1/applications/{row['applicationId']}/timeline")
        tp_review = next((e for e in (review.get("events") or [])
                          if e.get("stage") == "REVIEW"), None)
        if tp_review is None:
            return merged
        merged["events"] = [e for e in merged["events"] if e["stage"] != "REVIEW"]
        merged["events"].append(tp_review)
        merged["events"].sort(key=lambda e: self._STAGE_ORDER.get(e["stage"], 99))
        progressed = any(e["stage"] in {"G3", "G4", "D1", "D2", "D3", "D4", "D5", "D6", "FINAL", "PUB"}
                         for e in merged["events"])
        if not progressed and row["state"] not in {"issuing", "issue_failed"}:
            if tp_review.get("status") == "approved":
                merged["state"] = "approved"
            elif tp_review.get("status") == "rejected":
                merged["state"] = "rejected"
        return merged

    def timeline(self, owner: str, app_id: str) -> dict:
        """只读视图。"""
        merged = self._merge_review(self._row(owner, app_id))
        out = {"applicationId": app_id, "state": merged["state"],
               "events": merged["events"], "nextAction": self._next_action(merged),
               "catalog": merged.get("cmm", {}).get("categories", [])}
        if merged.get("issueFailure"):
            out["issueFailure"] = merged["issueFailure"]
        return out

    def decrypted_identity_demo(self, owner: str, app_id: str) -> dict:
        self._row(owner, app_id)
        return self.ctx.tp.get(
            f"/v1/applications/{app_id}/decrypted-demo")

    def scid_demo(self, owner: str, app_id: str) -> dict:
        self._row(owner, app_id)
        return self.ctx.phc.get(f"/v1/phc/{app_id}/scid-demo")

    def refresh(self, owner: str, app_id: str) -> dict:
        """推进动作之前调用：把上游审核结论固化到持久状态。"""
        row = self._row(owner, app_id)
        merged = self._merge_review(row)
        if merged["state"] != row["state"] or merged["events"] != row["events"]:
            row["state"] = merged["state"]
            row["events"] = merged["events"]
            self._save(row)
        return self.timeline(owner, app_id)

    @staticmethod
    def _next_action(row: dict) -> str | None:
        # 状态由已执行的转换落盘；失败事件只是展示，不能解锁后续动作。
        return {
            "approved": "issue",
            "awaiting_g4_acceptance": "accept-g4",
            "phc_accepted": "start-agent",
            "cmm_received": "build-agent",
            "awaiting_d5_acceptance": "accept-d5",
            "awaiting_d5_user_acceptance": "confirm-d5",
            "d5_accepted": "finalize-d6",
            "awaiting_final_verification": "verify-final",
            "awaiting_final_acceptance": "accept-final",
            "issuing": "reconcile",
            "issue_failed": "reconcile",
        }.get(row["state"])

    def issue(self, owner: str, app_id: str) -> dict:
        """签发。先把 `issuing` 落盘，再调上游。

        ★ 要处理的那个窗口：TP 已经算完并写了自己的记录，门户这边却在
          accept_rr 或写库时失败。如果不先落盘，门户完全不知道上游已经签发过，
          重试会撞上 TP 的 409，然后表现成"永远卡住"且没人知道为什么。
          落了 `issuing` 之后，失败状态可读、可对账（reconcile）。
        """
        self.refresh(owner, app_id)
        row = self._row(owner, app_id)
        if self._next_action(row) != "issue":
            raise ValueError("TP 尚未批准，或 PHC 已签发")
        executor = self._executor(owner)

        row["state"] = "issuing"
        row["issueAttempt"] = {"at": self.ctx.clock.now(), "stage": "upstream_issue"}
        self._save(row)

        try:
            issued = self.ctx.phc.post(f"/v1/phc/{app_id}/issue", {}, owner)
        except Exception as exc:                                   # noqa: BLE001
            self._mark_issue_failed(owner, app_id, "upstream_issue", exc)
            raise
        try:
            # 这一步之后上游已不可回滚：失败也必须记下"已签发"这个事实。
            row = self._row(owner, app_id)
            row["issueAttempt"] = {"at": self.ctx.clock.now(), "stage": "executor_accept",
                                   "phcVersion": issued["phcVersion"],
                                   "rrDigest": v1.json_digest(issued["rr"])}
            self._save(row)
            acceptance = executor.accept_rr(row["executorLabel"], issued["rr"], owner=owner,
                                            application_id=app_id)
        except Exception as exc:                                   # noqa: BLE001
            self._mark_issue_failed(owner, app_id, "executor_accept", exc,
                                    upstream_done=True)
            raise

        row = self._row(owner, app_id)
        row["events"] = [e for e in row["events"] if e["stage"] != "G3"]
        row["events"].append({"stage": "G3", "status": "issued_to_user_executor", "at": self.ctx.clock.now(),
                "artifacts": {"applicationId": app_id,
                              "sourceCRDigest": next(event["artifacts"]["crDigest"]
                                                     for event in row["events"]
                                                     if event["stage"] == "G1"),
                              "identityBindingVerifiedByTP": True,
                              "phcVersion": issued["phcVersion"],
                              "rrDigest": v1.json_digest(issued["rr"]),
                              "phcDigest": acceptance["phcDigest"],
                              "rrEnvelope": issued["rr"],
                              "executorAcceptance": "verified"}})
        row["state"] = "awaiting_g4_acceptance"
        row.pop("issueAttempt", None)
        row.pop("issueFailure", None)
        self._save(row)
        return self.timeline(owner, app_id)

    def _mark_issue_failed(self, owner: str, app_id: str, stage: str, exc: Exception,
                           *, upstream_done: bool = False) -> None:
        """把失败写成可读状态。`upstreamIssued` 决定对账往哪边走。"""
        row = self._row(owner, app_id)
        row["state"] = "issue_failed"
        row["issueFailure"] = {
            "at": self.ctx.clock.now(), "stage": stage,
            "error": type(exc).__name__, "message": str(exc)[:500],
            "upstreamIssued": upstream_done,
        }
        row["events"].append({"stage": "G3", "status": "failed", "at": self.ctx.clock.now(),
                              "artifacts": {"failedAt": stage,
                                            "upstreamIssued": upstream_done,
                                            "error": type(exc).__name__}})
        self._save(row)

    def reconcile(self, owner: str, app_id: str) -> dict:
        """显式对账：问 TP 到底签发了没有，据此把门户状态对齐。

        ★ 不自动重放 `/issue` —— 它不是幂等的（TP 对已签记录返回 409）。
          这里只读上游事实，然后把门户这边补齐：上游已签发就继续走执行器接受，
          上游没签发就退回 approved 让用户重新发起。
        """
        row = self._row(owner, app_id)
        if row["state"] not in {"issuing", "issue_failed"}:
            return self.timeline(owner, app_id)
        upstream = self.ctx.phc.get(f"/v1/phc/{app_id}")
        issued_upstream = bool(upstream.get("issued"))
        row = self._row(owner, app_id)
        if not issued_upstream:
            row["state"] = "approved"
            row["events"] = [e for e in row["events"]
                             if not (e["stage"] == "G3" and e["status"] == "failed")]
            row.pop("issueAttempt", None)
            row.pop("issueFailure", None)
            row["events"].append({"stage": "G3", "status": "reconciled_not_issued",
                                  "at": self.ctx.clock.now(),
                                  "artifacts": {"upstreamIssued": False}})
            self._save(row)
            return self.timeline(owner, app_id)
        # 上游已签发：门户不能自己造 RR，只能如实标记需要人工/上游补发
        row["state"] = "issue_failed"
        row["issueFailure"] = {**(row.get("issueFailure") or {}),
                               "upstreamIssued": True,
                               "reconciledAt": self.ctx.clock.now(),
                               "resolution": "上游已签发但本端未完成接受；"
                                             "需由上游重新投递 RR 或人工介入"}
        self._save(row)
        return self.timeline(owner, app_id)

    def accept_g4(self, owner: str, app_id: str) -> dict:
        self.refresh(owner, app_id)
        row = self._row(owner, app_id)
        if self._next_action(row) != "accept-g4":
            raise ValueError("G3 尚未签发，或 G4 已接受")
        result = self._executor(owner).accept_g4(row["executorLabel"], owner=owner,
                                                 application_id=app_id)
        row["events"].append({"stage": "G4", "status": "user_accepted", "at": self.ctx.clock.now(),
                              "artifacts": {k: result[k] for k in ("phcDigest", "phcVersion", "accepted")}})
        row["state"] = "phc_accepted"
        self._save(row)
        return self.timeline(owner, app_id)

    def begin_agent(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if self._next_action(row) != "start-agent":
            raise ValueError("必须先完成用户 G4 接受")
        executor = self._executor(owner)
        ar = executor.build_ar(row["executorLabel"], expires=self.ctx.clock.plus_hours(1),
                               owner=owner, application_id=app_id)
        opened = self.ctx.agent.post("/v1/tpaa/sessions",
                                     {"ar": ar, "applicationId": app_id}, owner)
        sid = opened["sessionId"]
        cmm = executor.open_cmm(row["executorLabel"], opened["cmm"], owner=owner,
                                application_id=app_id)
        row.update(sessionId=sid, cmm=cmm)
        row["events"] = [event for event in row["events"] if event["stage"] not in ("D1", "D2")]
        d1_event = next(event for event in reversed(executor.events(row["executorLabel"], owner=owner,
                                                                       application_id=app_id))
                        if event["stage"] == "D1")
        result = {"requestId": d1_event["artifacts"]["requestId"],
                  "cmmVersion": cmm["version"], "categories": cmm["categories"]}
        row["events"].append({"stage": "D1", "status": "complete", "at": self.ctx.clock.now(), "artifacts": result})
        row["events"].append({"stage": "D2", "status": "complete", "at": self.ctx.clock.now(),
                              "artifacts": {"sessionId": sid, "cmmVersion": cmm["version"],
                                            "moduleCount": sum(len(x["options"]) for x in cmm["categories"]),
                                            "cmm": cmm}})
        row["state"] = "cmm_received"
        self._save(row)
        return self.timeline(owner, app_id)

    def build_agent(self, owner: str, app_id: str, selection: list[dict]) -> dict:
        row = self._row(owner, app_id)
        if self._next_action(row) != "build-agent":
            raise ValueError("尚未取得 CMM 或 D4 已构建")
        if not isinstance(selection, list) or not selection:
            raise ValueError("必须从 AP 返回的 CMM 中选择至少一个模块")
        offered = {(category["id"], version) for category in row["cmm"]["categories"] for version in category["options"]}
        if any((item.get("moduleId"), item.get("version")) not in offered for item in selection):
            raise ValueError("选择中包含 CMM 未提供的模块或版本")
        executor = self._executor(owner)
        paci = executor.build_paci(row["executorLabel"], selection=selection,
                                   owner=owner, application_id=app_id)
        result = self.ctx.agent.post(f"/v1/tpaa/sessions/{row['sessionId']}/build", {"paci": paci}, owner)
        row["recordId"] = result["recordId"]
        row["events"].append({"stage": "D3", "status": "user_confirmed", "at": self.ctx.clock.now(),
                              "artifacts": {"selection": selection, "selectionDigest": v1.json_digest(selection),
                                            "cmmVersion": row["cmm"]["version"]}})
        d4_artifacts = {"recordId": result["recordId"],
                        "cmi": result["event"]["artifacts"]["cmi"],
                        "moduleCount": result["event"]["artifacts"].get("moduleCount", len(selection)),
                        "modules": result["event"]["artifacts"].get("modules", []),
                        "cmiAlgorithm": result["event"]["artifacts"].get(
                            "cmiAlgorithm", "CMI=HCGen(CMC,H(ID))"),
                        "cmiInputOrder": result["event"]["artifacts"].get(
                            "cmiInputOrder", "CMM category order; order is significant"),
                        "hashCalculations": {
                            "hashFunction": "SHA-256",
                            "encoding": "TPAA/v1 length-prefixed typed encoding with domain-separated tags",
                            "cmiFormula": "c0=H('HCGen/seed',H(ID)); ci=H('HCGen/link',ci-1,moduleId,version,digest)",
                            "identityInput": "H(ID) is computed from submitted ID inside the protocol; value is intentionally not displayed",
                            "selectionDigest": next(
                                event["artifacts"]["selectionDigest"]
                                for event in reversed(row["events"])
                                if event["stage"] == "D3"),
                            "parDigest": v1.json_digest(result["par"]),
                            "steps": [
                                {"index": index + 1,
                                 "formula": f"c{index + 1}=H('HCGen/link',c{index},moduleId,version,digest)",
                                 "moduleId": module["moduleId"],
                                 "version": module["version"],
                                 "digest": module["digest"],
                                 "result": "computed; intermediate chain value withheld"}
                                for index, module in enumerate(
                                    result["event"]["artifacts"].get("modules", []))
                            ],
                            "result": result["event"]["artifacts"]["cmi"],
                        },
                        "parDigest": v1.json_digest(result["par"])}
        if result["event"]["artifacts"].get("recoveredFromRecordId"):
            d4_artifacts["recoveredFromRecordId"] = result["event"]["artifacts"]["recoveredFromRecordId"]
        row["events"].append({"stage": "D4", "status": "complete", "at": self.ctx.clock.now(),
                              "artifacts": d4_artifacts})
        row["par"] = result["par"]
        row["state"] = "awaiting_d5_acceptance"
        self._save(row)
        return self.timeline(owner, app_id)

    def accept_d5(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if self._next_action(row) != "accept-d5":
            raise ValueError("D4 尚未完成，或 D5 已核验")
        executor = self._executor(owner)
        modules = executor.accept_par(row["executorLabel"], row["par"], owner=owner,
                                      application_id=app_id)
        row["events"].append({"stage": "D5", "status": "verified_by_user_executor", "at": self.ctx.clock.now(),
                              "artifacts": {"cmi": modules["cmi"], "modules": modules["modules"],
                                            "cmiAlgorithm": modules["cmiAlgorithm"],
                                            "cmiInputOrder": modules["cmiInputOrder"],
                                            "phc": modules["phc"],
                                            "phcDigest": modules["phcDigest"],
                                            "phcVersion": modules["phcVersion"],
                                            "d4Statement": modules["d4Statement"],
                                            "domain2": modules["domain2"],
                                            "statementDigest": modules["statementDigest"],
                                            "hashCalculations": {
                                                "hashFunction": "SHA-256",
                                                "encoding": "TPAA/v1 length-prefixed typed encoding with domain-separated tags",
                                                "cmiRecomputedByUser": modules["cmi"],
                                                "phcDigest": modules["phcDigest"],
                                                "modulesDigest": modules["d4Statement"]["modulesDigest"],
                                                "afRef": modules["d4Statement"]["afRef"],
                                                "statementDigest": modules["statementDigest"],
                                                "statementSignatureVerified": True,
                                            },
                                            "cmiRecomputed": True, "userConfirmationRequired": True}})
        row["state"] = "awaiting_d5_user_acceptance"
        self._save(row)
        return self.timeline(owner, app_id)

    def confirm_d5(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if row["state"] != "awaiting_d5_user_acceptance":
            raise ValueError("当前没有等待用户确认的 D5 结果")
        didgr = self._executor(owner).build_didgr(
            row["executorLabel"], expires=self.ctx.clock.plus_hours(1), owner=owner,
            application_id=app_id)
        row["didgr"] = didgr
        row["events"][-1]["artifacts"]["userAccepted"] = True
        row["state"] = "d5_accepted"
        self._save(row)
        return self.timeline(owner, app_id)

    def finalize_d6(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if row["state"] != "d5_accepted":
            raise ValueError("必须先接受 D5")
        executor = self._executor(owner)
        final = self.ctx.phc.post(f"/v1/phc/{app_id}/finalize", {"didgr": row["didgr"]}, owner)
        row["final"] = final["final"]
        row["finalizationAttestation"] = final["attestation"]
        row["events"].append({"stage": "D6", "status": "issued_to_user_executor", "at": self.ctx.clock.now(),
                              "artifacts": {"phcDigest": final["attestation"]["phcDigest"],
                                            "phcVersion": final["phcVersion"],
                                            "finalEnvelope": final["final"],
                                            "cmi": final["event"]["artifacts"]["cmi"],
                                            "did": final["event"]["artifacts"]["did"]}})
        row["state"] = "awaiting_final_verification"
        self._save(row)
        return self.timeline(owner, app_id)

    def verify_final(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if row["state"] == "awaiting_final_acceptance":
            return self.timeline(owner, app_id)
        if row["state"] != "awaiting_final_verification":
            raise ValueError("当前没有等待核验的 FINAL 凭证")
        result = self._executor(owner).verify_final(
            row["executorLabel"], row["final"], row["finalizationAttestation"],
            owner=owner, application_id=app_id)
        row["events"].append({"stage": "FINAL", "status": "verified_by_user_executor",
                              "at": self.ctx.clock.now(),
                              "artifacts": {k: result[k] for k in ("did", "phcDigest",
                                                                   "phcVersion", "cmi")}})
        row["state"] = "awaiting_final_acceptance"
        self._save(row)
        return self.timeline(owner, app_id)

    def accept_final(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if row["state"] == "d6_accepted":
            return self.timeline(owner, app_id)
        if row["state"] != "awaiting_final_acceptance":
            raise ValueError("必须先通过用户端 FINAL 核验")
        result = self._executor(owner).accept_final(row["executorLabel"], owner=owner,
                                                   application_id=app_id)
        row["events"].append({"stage": "FINAL", "status": "user_accepted",
                              "at": self.ctx.clock.now(),
                              "artifacts": {k: result[k] for k in ("did", "phcDigest", "phcVersion")}})
        row["state"] = "d6_accepted"
        self._save(row)
        return self.timeline(owner, app_id)

    def publish(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if self._next_action(row) != "publish":
            raise ValueError("用户端尚未接受 D6")
        executor = self._executor(owner)
        receipt = executor.publication_receipt(row["executorLabel"], owner=owner,
                                               application_id=app_id)
        published = self.ctx.agent.post(f"/v1/tpaa/records/{row['recordId']}/publish", {"receipt": receipt}, owner)
        event = {"stage": "PUB", "status": "published", "at": self.ctx.clock.now(),
                 "artifacts": {k: published[k] for k in
                               ("recordId", "did", "phcDigest", "cmi", "buildDigest", "status")}}
        row["events"].append(event)
        row["state"] = "published"
        self._save(row)
        return self.timeline(owner, app_id)

    def start_runtime(self, owner: str, app_id: str) -> dict:
        row = self._row(owner, app_id)
        if row["state"] == "agent_constructed":
            return self.timeline(owner, app_id)
        if self._next_action(row) != "start-runtime":
            raise ValueError("只有已发布并已接受 FINAL 的制品才能启动 Runtime")
        executor = self._executor(owner)
        credential = executor.credential(row["executorLabel"], owner=owner,
                                         application_id=app_id)
        runtime = self.ctx.agent.post(
            f"/v1/tpaa/publications/{row['recordId']}/runtime",
            {"did": credential["did"], "phc": credential["phc"]}, owner)
        row["events"].append({
            "stage": "RUN", "status": "constructed", "at": self.ctx.clock.now(),
            "artifacts": {key: runtime[key] for key in
                          ("runtimeId", "did", "buildDigest", "manifestDigest",
                           "verifiedTools", "status", "model")},
        })
        row["state"] = "agent_constructed"
        self._save(row)
        return self.timeline(owner, app_id)

    def _save(self, row: dict) -> None:
        def update(data):
            current = data.setdefault("applications", {}).get(row["applicationId"])
            if current is None or current["owner"] != row["owner"]:
                raise NotFound("申请状态已不存在")
            data["applications"][row["applicationId"]] = row
            return data
        self.ctx.store.update(update)


def create_app(*, ctx: PortalContext) -> FastAPI:
    app = FastAPI(title="portal-api", version="1.0.0")
    app.state.domain = "user-side"
    app.state.ctx = ctx
    app.state.desk = desk = PortalDesk(ctx)
    app.state.local_sessions = LocalBrowserSessions(clock=time.time)
    app.state.local_browser_auth = os.environ.get("TPAA_LOCAL_TEST_AUTH") == "1"
    app.state.local_browser_origin = os.environ.get("TPAA_LOCAL_BROWSER_ORIGIN", "http://127.0.0.1:5173")
    install_errors(app)
    install_auth_routes(app, ctx.auth)
    guard = ctx.auth.verifier()

    @app.exception_handler(Exception)
    async def portal_error(request, exc: Exception):
        from services.shared.v1_http import log
        log.exception("portal request failed: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"code": "INTERNAL_ERROR",
                                                      "message": "Portal 内部错误，请查看服务端日志"})

    def local_user(request: Request) -> dict:
        if app.state.local_browser_auth:
            return require_session(request, app.state.local_sessions)
        authorization = request.headers.get("authorization")
        claims = ctx.auth.verifier().check(authorization)
        if claims.get("role") != "user":
            raise Forbidden("需要角色 user")
        return claims

    def require_user(request: Request, *, mutation: bool = False) -> dict:
        if app.state.local_browser_auth:
            claims = require_session(request, app.state.local_sessions)
            if mutation:
                same_origin(request, app.state.local_browser_origin)
            return claims
        authorization = request.headers.get("authorization")
        claims = ctx.auth.verifier().check(authorization)
        if claims.get("role") != "user":
            raise Forbidden("需要角色 user")
        return claims

    @app.post("/api/user/v1/local-session")
    def start_local_session(request: Request):
        if not app.state.local_browser_auth or ctx.execution_profile != "test-adapter":
            raise NotFound("local test-adapter browser session is disabled")
        same_origin(request, app.state.local_browser_origin)
        owner = next(iter(ctx.handlers or {}), None)
        if not owner:
            raise HTTPException(status_code=503, detail="local executor owner is not configured")
        session_id, ttl = app.state.local_sessions.create(owner)
        response = JSONResponse({"enabled": True, "profile": "test-adapter", "owner": owner,
                                 "userControlledExecution": False, "expiresIn": ttl,
                                 "identity": "local test-adapter identity; not proof of user-controlled keys"})
        response.set_cookie(COOKIE_NAME, session_id, max_age=ttl, httponly=True,
                            secure=request.url.scheme == "https", samesite="strict",
                            path="/api/user/v1")
        return response

    @app.get("/api/user/v1/local-session")
    def local_session_status(request: Request):
        if not app.state.local_browser_auth:
            return {"enabled": False, "authenticated": False, "owner": None}
        owner = app.state.local_sessions.owner(request.cookies.get(COOKIE_NAME))
        return {"enabled": True, "authenticated": owner is not None,
                "owner": owner, "profile": "test-adapter",
                "userControlledExecution": False}

    @app.delete("/api/user/v1/local-session")
    def end_local_session(request: Request):
        if not app.state.local_browser_auth:
            raise NotFound("local test-adapter browser session is disabled")
        same_origin(request, app.state.local_browser_origin)
        app.state.local_sessions.revoke(request.cookies.get(COOKIE_NAME))
        response = JSONResponse({"loggedOut": True})
        response.delete_cookie(COOKIE_NAME, path="/api/user/v1", httponly=True, samesite="strict")
        return response

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "portal-api", "profile": "tpaa_v1"}

    @app.get("/api/user/v1/initialize")
    def initialize(request: Request):
        who = require_user(request)
        return desk.initialize(who["sub"])

    @app.get("/api/user/v1/applications")
    def applications(request: Request):
        who = require_user(request)
        return desk.list_applications(who["sub"])

    @app.post("/api/user/v1/applications")
    def create(body: dict = Body(...), request: Request = None):
        who = require_user(request, mutation=True)
        return desk.create_application(who["sub"], body)

    @app.get("/api/user/v1/applications/{app_id}/timeline")
    def timeline(app_id: str, request: Request):
        who = require_user(request)
        return desk.timeline(who["sub"], app_id)

    @app.get("/api/user/v1/applications/{app_id}/decrypted-demo")
    def decrypted_demo(app_id: str, request: Request):
        who = require_user(request)
        return desk.decrypted_identity_demo(who["sub"], app_id)

    @app.get("/api/user/v1/applications/{app_id}/scid-demo")
    def scid_demo(app_id: str, request: Request):
        who = require_user(request)
        return desk.scid_demo(who["sub"], app_id)

    @app.post("/api/user/v1/applications/{app_id}/{action}")
    def transition(app_id: str, action: str, request: Request,
                   body: dict = Body(default={})):
        who = require_user(request, mutation=True)
        actions = {"issue": lambda: desk.issue(who["sub"], app_id),
                   "accept-g4": lambda: desk.accept_g4(who["sub"], app_id),
                   "begin-agent": lambda: desk.begin_agent(who["sub"], app_id),
                   "build-agent": lambda: desk.build_agent(who["sub"], app_id, body.get("selection", [])),
                   "accept-d5": lambda: desk.accept_d5(who["sub"], app_id),
                   "confirm-d5": lambda: desk.confirm_d5(who["sub"], app_id),
                   "finalize-d6": lambda: desk.finalize_d6(who["sub"], app_id),
                   "verify-final": lambda: desk.verify_final(who["sub"], app_id),
                   "accept-final": lambda: desk.accept_final(who["sub"], app_id),
                   "reconcile": lambda: desk.reconcile(who["sub"], app_id)}
        if action not in actions:
            raise NotFound(f"不支持的流程动作：{action}")
        return actions[action]()

    return app


def _from_env():
    from services.shared.v1_http import SystemClock, assert_single_worker
    from services.user_side.portal_api.infra.production import build_context
    assert_single_worker("portal-api")
    clock = SystemClock()
    return create_app(ctx=build_context(clock=clock))


class _PortalApp(LazyApp):
    async def __call__(self, scope, receive, send):
        try:
            inner = self._get()
        except Exception:
            from services.shared.v1_http import log
            log.exception("portal startup failed")
            response = JSONResponse(status_code=503, content={
                "code": "PORTAL_NOT_READY",
                "message": "Portal 尚未就绪，请检查服务端启动配置与依赖服务",
            })
            await response(scope, receive, send)
            return
        await inner(scope, receive, send)


app = _PortalApp(_from_env)

__all__ = ["PortalContext", "PortalDesk", "DomainPort", "create_app", "app"]
