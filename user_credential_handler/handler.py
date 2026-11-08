"""Service-held tpaa_v1 credential state for local development and tests.

This implementation stores a USER key seed in keys.json and is NOT a user-controlled
wallet or a production key custody solution. Production callers must inject a secure
USER HSM handle and use an independently controlled acceptance interface.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime
from pathlib import Path

import crypto.sdk
from localstore.paths import write_atomic

v1 = crypto.sdk.v1


class _Store:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def update(self, fn) -> dict:
        d = self.load()
        out = fn(d)
        d = out if out is not None else d
        write_atomic(self.path, json.dumps(d, ensure_ascii=False, indent=2).encode())
        return d


class CredentialHandlerError(RuntimeError):
    pass


class UserCredentialHandler:
    # This service-held key implementation must never be advertised as a
    # user-controlled signer, even when the server runs on the user's machine.
    user_controlled = False

    def __init__(self, directory: str | Path, *, hsm=None) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.hsm = hsm or self._load_or_create_hsm()
        self.store = _Store(self.dir / "state.json")

    @property
    def sign_pk_hex(self) -> str:
        return v1.pk_hex(self.hsm.pubkey())

    @property
    def owner(self) -> str:
        return v1.owner_of(self.hsm.pubkey())

    def login_body(self, challenge: dict) -> dict:
        return {"challenge": challenge["challenge"], "signPk": self.sign_pk_hex,
                "sig": v1.auth.sign_login(self.hsm, challenge=challenge["challenge"],
                                          aud=challenge["aud"])}

    def build_cr(self, *, label: str, pii: dict, bi: dict, tp_keys: dict, ap_keys: dict,
                 tp_slot: dict, ap_slot: dict, expires: str,
                 request_id: str | None = None, identity_evidence: dict | None = None) -> dict:
        if identity_evidence is not None and not request_id:
            raise CredentialHandlerError("带身份核验证据的 CR 必须预先确定 requestId")
        rid = request_id or "cr-" + secrets.token_hex(8)
        cr, pending = v1.user.g1_build_cr(
            user_hsm=self.hsm, pii=pii, bi=bi, tp_enc_pk=int(tp_keys["encPub"], 16),
            tp_slot=(tp_slot["nonce"], int(tp_slot["pub"], 16)),
            ap_slot=(ap_slot["nonce"], int(ap_slot["pub"], 16)),
            ap_sign_pk=v1.pk_from_hex(ap_keys["signPk"]), request_id=rid, expires=expires,
            identity_evidence=identity_evidence)
        self._put(label, {"stage": "pending", "pending": v1.records.dump(pending),
                          "tpKeys": tp_keys, "apKeys": ap_keys,
                          "events": [{"stage": "G1", "status": "complete", "requestId": rid,
                                      "artifacts": {"crDigest": v1.json_digest(cr),
                                                    "owner": self.owner}}]})
        return cr

    def public_signing_key(self) -> str:
        return self.sign_pk_hex

    def accept_rr(self, label: str, rr: dict) -> dict:
        e = self._get(label, "pending")
        cred = v1.user.g4_accept_rr(user_hsm=self.hsm, rr_box=rr,
                                    pending=v1.records.load(e["pending"]), **self._pks(e))
        self._patch(label, stage="cred", cred=v1.records.dump(cred))
        result = {"phcDigest": v1.phc_digest(v1.from_jsonld(cred.phc)),
                  "phcVersion": v1.from_jsonld(cred.phc).version,
                  "phc": cred.phc, "accepted": True}
        self._event(label, "G4", result)
        return result

    def accept_g4(self, label: str) -> dict:
        e = self._get(label, "cred")
        cred = v1.records.load(e["cred"])
        self._patch(label, stage="g4_accepted")
        result = {"phcDigest": v1.phc_digest(v1.from_jsonld(cred.phc)),
                  "phcVersion": v1.from_jsonld(cred.phc).version,
                  "phc": cred.phc, "accepted": True}
        self._event(label, "G4", result)
        return result

    def application_id(self, label: str) -> str | None:
        entry = self.store.load().get(label)
        return None if entry is None else entry.get("applicationId")

    def set_application(self, label: str, app_id: str) -> None:
        if not isinstance(app_id, str) or not app_id:
            raise CredentialHandlerError("缺少有效的申请编号")

        def _upd(data):
            entry = data.get(label)
            if entry is None:
                raise CredentialHandlerError(f"凭证处理器里没有申请 {label!r}")
            bound = entry.get("applicationId")
            if bound is not None and bound != app_id:
                raise CredentialHandlerError("执行器申请绑定不能被替换")
            entry["applicationId"] = app_id
            return data

        self.store.update(_upd)
        if not any(event.get("stage") == "G1" and
                   event.get("artifacts", {}).get("applicationId") == app_id
                   for event in self.events(label)):
            self._event(label, "G1", {"applicationId": app_id}, status="accepted_by_tp")

    def pending_request(self, label: str) -> dict:
        e = self._get(label, "pending")
        pending = v1.records.load(e["pending"])
        g1 = next(event for event in e.get("events", []) if event.get("stage") == "G1")
        return {"requestId": pending.request_id, "tpNonce": pending.tp_nonce,
                "apNonce": pending.ap_nonce,
                "sealedCrDigest": g1["artifacts"]["crDigest"]}

    def build_ar(self, label: str, *, expires: str) -> dict:
        e = self._get_any(label, "cred", "g4_accepted")
        request_id = "ar-" + secrets.token_hex(8)
        ar = v1.user.d1_build_ar(user_hsm=self.hsm, cred=v1.records.load(e["cred"]),
                                 ap_enc_pk=int(e["apKeys"]["encPub"], 16),
                                 request_id=request_id, expires=expires)
        self._event(label, "D1", {"requestId": request_id})
        return ar

    def open_cmm(self, label: str, cmm_box: dict) -> dict:
        self._get_any(label, "cred", "g4_accepted")
        cmm = v1.user.d3_open_cmm(user_hsm=self.hsm, cmm_box=cmm_box)
        self._patch(label, cmm=cmm)
        self._event(label, "D2", {"cmmVersion": cmm.get("version"),
                                   "moduleCount": sum(len(c["options"]) for c in cmm["categories"])})
        return cmm

    def build_paci(self, label: str, *, selection: list[dict]) -> dict:
        e = self._get_any(label, "cred", "g4_accepted")
        if "cmm" not in e:
            raise CredentialHandlerError("还没收到 CMM，不能提交选择")
        offered = {(c["id"], o) for c in e["cmm"]["categories"] for o in c["options"]}
        for selected in selection:
            if (selected["moduleId"], selected["version"]) not in offered:
                raise CredentialHandlerError("选择包含 CMM 未提供的模块版本")
        paci = v1.user.d3_build_paci(user_hsm=self.hsm, ap_enc_pk=int(e["apKeys"]["encPub"], 16),
                                     cmm_version=e["cmm"]["version"], selection=selection,
                                     request_id="paci-" + secrets.token_hex(8))
        self._event(label, "D3", {"selection": selection,
                                   "selectionDigest": v1.json_digest(selection),
                                   "cmmVersion": e["cmm"]["version"]})
        return paci

    def accept_par(self, label: str, par: dict) -> dict:
        e = self._get_any(label, "cred", "g4_accepted")
        # applicationId 传进去：D5 要确认 AP 的声明确实是针对本执行标签这张申请签的。
        verified = v1.user.d5_accept_par(user_hsm=self.hsm, par_box=par,
                                         cred=v1.records.load(e["cred"]),
                                         application_id=e.get("applicationId") or "",
                                         **self._pks(e))
        self._patch(label, stage="verified", verified=v1.records.dump(verified))
        result = {"cmi": verified.cmi, "modules": verified.pa["modules"], "accepted": True,
                  "domain2": verified.statement.get("domain2", ""),
                  "phc": verified.phc1,
                  "phcDigest": v1.phc_digest(v1.from_jsonld(verified.phc1)),
                  "phcVersion": v1.from_jsonld(verified.phc1).version,
                  "cmiAlgorithm": "CMI=HCGen(ordered modules,H(ID)); c0=H('HCGen/seed',H(ID)); ci=H('HCGen/link',ci-1,moduleId,version,digest)",
                  "cmiInputOrder": "Ordered module list; order is significant",
                  "d4Statement": verified.statement,
                  "statementDigest": v1.json_digest(
                      {k: v for k, v in verified.statement.items() if k != "sig"})}
        self._event(label, "D5", result)
        return result

    def build_didgr(self, label: str, *, expires: str) -> dict:
        e = self._get(label, "verified")
        return v1.user.d5_build_didgr(user_hsm=self.hsm, verified=v1.records.load(e["verified"]),
                                      tp_enc_pk=int(e["tpKeys"]["encPub"], 16),
                                      request_id="didgr-" + secrets.token_hex(8), expires=expires)

    def verify_final(self, label: str, final: dict, finalization_attestation: dict) -> dict:
        e = self._get(label, "verified")
        verified = v1.records.load(e["verified"])
        did, phc2 = v1.user.d6_accept_final(user_hsm=self.hsm, final_box=final,
                                            verified=verified, **self._pks(e))
        statement = dict(finalization_attestation)
        sig = statement.pop("sig", "")
        v1.check_sig(self._pks(e)["tp_sign_pk"], sig, "FinalizationAttestation",
                     v1.json_digest(statement), what="TP D6 完成声明")
        if (statement.get("applicationId") != e.get("applicationId")
                or statement.get("owner") != self.owner
                or statement.get("userSignPk") != self.sign_pk_hex
                or statement.get("did") != did
                or statement.get("phcDigest") != v1.phc_digest(v1.from_jsonld(phc2))
                or statement.get("cmi") != verified.cmi):
            raise v1.ProtocolError("TP D6 完成声明与用户凭证处理器验证的最终凭证不一致")
        self._patch(label, stage="final_verified", pendingFinal={
            "did": did, "phc": phc2, "attestation": finalization_attestation,
            "phcDigest": statement["phcDigest"],
            "phcVersion": v1.from_jsonld(phc2).version,
        })
        result = {"did": did, "phc": phc2, "phcDigest": statement["phcDigest"],
                  "phcVersion": v1.from_jsonld(phc2).version, "cmi": verified.cmi,
                  "verified": True}
        self._event(label, "FINAL", result, status="verified_by_user_executor")
        return result

    def accept_final(self, label: str) -> dict:
        e = self._get(label, "final_verified")
        final = e["pendingFinal"]
        self._patch(label, stage="final", did=final["did"], phc=final["phc"],
                    finalizationAttestation=final["attestation"])
        result = {"did": final["did"], "phcDigest": final["phcDigest"],
                  "phcVersion": final["phcVersion"], "accepted": True}
        self._event(label, "FINAL", result, status="user_accepted")
        return result

    def publication_receipt(self, label: str) -> dict:
        e = self._get(label, "final")
        verified = v1.records.load(e["verified"])
        body = {"version": "tpaa-v1-publication-receipt", "owner": self.owner,
                "userSignPk": self.sign_pk_hex, "applicationId": e["applicationId"],
                "did": e["did"], "phcDigest": v1.phc_digest(v1.from_jsonld(e["phc"])),
                "cmi": verified.cmi, "modulesDigest": v1.json_digest(verified.pa["modules"]),
                "finalizationAttestation": e["finalizationAttestation"]}
        return {**body, "sig": v1.sign(self.hsm, "PublicationReceipt", v1.json_digest(body))}

    def events(self, label: str) -> list[dict]:
        return list(self.store.load().get(label, {}).get("events", []))

    # ---- requestId 幂等（落盘，重启后仍然生效）----
    def replay(self, label: str, operation: str, request_id: str):
        """同一 (label, operation, requestId) 的首次结果；没有则 None。

        ★ 为什么必须落盘而不是放内存：accept-rr / accept-final 都不是幂等动作，
          进程重启后客户端重试同一个号，内存表已经空了，二次执行会把状态推错。
        """
        key = f"{operation}:{request_id}"
        return self.store.load().get(label, {}).get("requestIds", {}).get(key)

    def remember(self, label: str, operation: str, request_id: str, result: dict) -> None:
        key = f"{operation}:{request_id}"

        def _upd(d):
            entry = d.get(label)
            if entry is None:                 # set-application 之前标签还不存在
                entry = d.setdefault(label, {})
            entry.setdefault("requestIds", {})[key] = result
            return d

        self.store.update(_upd)

    def _event(self, label: str, stage: str, artifacts: dict, *, status: str = "complete") -> None:
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        def _upd(data):
            data[label].setdefault("events", []).append({
                "stage": stage, "status": status, "at": now, "artifacts": artifacts})
            return data
        self.store.update(_upd)

    def credential(self, label: str) -> dict:
        e = self._get(label, "final")
        return {"did": e["did"], "phc": e["phc"]}

    def _pks(self, e: dict) -> dict:
        return {"tp_sign_pk": v1.pk_from_hex(e["tpKeys"]["signPk"]),
                "ap_sign_pk": v1.pk_from_hex(e["apKeys"]["signPk"])}

    def _get_any(self, label: str, *stages: str) -> dict:
        e = self.store.load().get(label)
        if e is None:
            raise CredentialHandlerError(f"凭证处理器里没有申请 {label!r}")
        if e["stage"] not in stages:
            raise CredentialHandlerError(f"申请 {label!r} 当前处于 {e['stage']}，这一步要求 {'/'.join(stages)}")
        return e

    def _get(self, label: str, stage: str) -> dict:
        e = self.store.load().get(label)
        if e is None:
            raise CredentialHandlerError(f"凭证处理器里没有申请 {label!r}")
        if e["stage"] != stage:
            raise CredentialHandlerError(f"申请 {label!r} 当前处于 {e['stage']}，这一步要求 {stage}")
        return e

    def _put(self, label: str, entry: dict) -> None:
        def _upd(d):
            if label in d:
                raise CredentialHandlerError(f"凭证处理器里已有同名申请 {label!r}")
            d[label] = entry
            return d
        self.store.update(_upd)

    def _patch(self, label: str, **kw) -> None:
        def _upd(d):
            d[label].update(kw)
            return d
        self.store.update(_upd)

    def _load_or_create_hsm(self):
        p = self.dir / "keys.json"
        if p.exists():
            k = json.loads(p.read_text(encoding="utf-8"))
        else:
            k = v1.new_hsm_seed()
            p.write_text(json.dumps(k, indent=2), encoding="utf-8")
        return v1.hsm_from_seed(domain="USER", seed=k)


__all__ = ["UserCredentialHandler", "CredentialHandlerError"]
