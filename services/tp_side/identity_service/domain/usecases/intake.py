"""identity-service 用例：TP 槽位、CR 受理、审核视图、签发前的受控取件。

★ 库里只存 **CR 密文**与少量非敏感元数据（申请号、摘要、状态、受理时间）。
  BI / PII 明文只在两个时刻出现在内存里：
      审核员打开审核视图（字段已掩码）
      phc-service 取件签发（经进程内端口，不走公网接口）
  这样"审核员不下载原件"不只是工作台规矩，库里本来就没有原件可下。
"""

from __future__ import annotations

import secrets

import crypto.sdk

from services.shared.v1_http import Forbidden, NotFound, claim_request_id

v1 = crypto.sdk.v1


def _mask(v) -> str:
    s = str(v)
    if len(s) <= 2:
        return "*" * len(s)
    keep = max(1, len(s) // 6)
    return s[:keep] + "*" * (len(s) - 2 * keep) + s[-keep:]


class IdentityIntake:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    # ---- 前置：分配 TP 槽位（errata E1）----
    def allocate_slot(self, *, user_sign_pk_hex: str, caller: str) -> dict:
        """caller = 令牌里的 sub。只能为自己的签名公钥分配槽位。"""
        owner = v1.owner_of(v1.pk_from_hex(user_sign_pk_hex))
        if owner != caller:
            raise Forbidden("只能为自己的签名公钥申请槽位")
        nonce, t_pub = self.ctx.tp_hsm.allocate_slot(owner)
        return {"nonce": nonce, "pub": format(t_pub, "x")}

    # ---- G2-a 受理 ----
    def submit(self, *, cr_box: dict, caller: str) -> dict:
        now = self.ctx.clock.now()
        opened = v1.tp.tp_open_cr(tp_hsm=self.ctx.tp_hsm, cr_box=cr_box, now=now)
        if opened.owner != caller:
            # CR 里的用户签名已经证明了"谁签的"；这里再要求"谁提交的"与之一致，
            # 否则任何登录用户都能把截获的别人的 CR 转交上来，占掉对方的 requestId
            raise Forbidden("CR 的签名人与登录用户不一致")
        self._verify_evidence(opened, now)
        claim_request_id(self.ctx.store, "CR", opened.request_id, now)
        app_id = "app-" + secrets.token_hex(12)

        def _put(d):
            d.setdefault("apps", {})[app_id] = {
                "crBox": cr_box, "receivedAt": now, "crDigest": opened.cr_digest,
                "requestId": opened.request_id, "state": "pending_review",
                "owner": opened.owner,
                "reviewMetadata": self.review_metadata(opened),
            }
            return d

        self.ctx.store.update(_put)
        self.ctx.audit("identity.cr_received", app_id, {"crDigest": opened.cr_digest})
        return {"applicationId": app_id, "crDigest": opened.cr_digest, "state": "pending_review"}

    def progress(self, app_id: str, *, caller: str) -> dict:
        app = self._get(app_id)
        if app["owner"] != caller:
            raise Forbidden("只能查看自己的申请进度")
        review_view = self.ctx.progress_review(app_id)
        return {"applicationId": app_id, "state": app["state"],
                "crDigest": app["crDigest"], "receivedAt": app["receivedAt"],
                "review": review_view}

    def review_queue(self) -> dict:
        """Reviewer-only read model: masked fields and decision state only."""
        apps = self.ctx.store.load().get("apps", {})
        items = []
        for app_id, app in apps.items():
            metadata = app.get("reviewMetadata")
            if not self.has_review_metadata(metadata):
                metadata = self.review_metadata(self._reopen(app))
            review = self.ctx.progress_review(app_id)
            review_safe = None if review is None else {
                "applicationId": review.get("applicationId", app_id),
                "state": review.get("state", app["state"]),
                "approved": bool(review.get("approved")),
                "decisions": [{k: decision[k] for k in ("reviewer", "decision", "at")
                               if k in decision} for decision in review.get("decisions", [])],
            }
            items.append({
                "applicationId": app_id,
                "crDigest": app["crDigest"],
                "receivedAt": app["receivedAt"],
                "state": (review or {}).get("state", app["state"]),
                "pii": metadata["pii"],
                "biFields": metadata["biFields"],
                "review": review_safe,
            })
        items.sort(key=lambda item: (item["receivedAt"], item["applicationId"]))
        return {"items": items}

    def review_view(self, app_id: str) -> dict:
        app = self._get(app_id)
        opened = self._reopen(app)
        review = self.ctx.progress_review(app_id)
        review_safe = None if review is None else {
            "applicationId": review.get("applicationId", app_id),
            "state": review.get("state", app["state"]),
            "approved": bool(review.get("approved")),
            "decisions": [{k: decision[k] for k in ("reviewer", "decision", "at")
                           if k in decision} for decision in review.get("decisions", [])],
        }
        result = {
            "applicationId": app_id, "crDigest": app["crDigest"],
            "state": (review or {}).get("state", app["state"]),
            "receivedAt": app["receivedAt"],
            "pii": {k: _mask(v) for k, v in opened.pii.items()},
            "biFields": sorted(opened.bi.keys()),          # 默认只返回项目名；演示照片预览单独受控
            "review": review_safe,
        }
        photo = opened.bi.get("facePhoto")
        if (getattr(self.ctx, "demo_photo_preview", False) and isinstance(photo, str)
                and len(photo) <= 90 * 1024
                and photo.startswith(("data:image/jpeg;base64,", "data:image/png;base64,",
                                      "data:image/webp;base64,"))):
            result["demoFacePhotoPreview"] = photo
        return result

    def decrypted_demo_view(self, app_id: str, *, caller: str) -> dict:
        """Owner-only, redacted plaintext preview for the local protocol demonstration."""
        app = self._get(app_id)
        if app["owner"] != caller:
            raise Forbidden("只能查看自己的身份申请")
        opened = self._reopen(app)
        photo = opened.bi.get("facePhoto")
        photo_info = None
        if isinstance(photo, str) and photo.startswith("data:image/") and "," in photo:
            header, encoded = photo.split(",", 1)
            photo_info = {
                "present": True,
                "mediaType": header[5:].split(";", 1)[0],
                "encodedBytes": len(encoded.encode("utf-8")),
            }
        return {
            "applicationId": app_id,
            "decryptedBy": "TP identity-service",
            "signatureVerified": True,
            "pii": {key: _mask(value) for key, value in opened.pii.items()},
            "biFields": sorted(opened.bi.keys()),
            "facePhoto": photo_info,
            "hashCalculations": {
                "hashFunction": "SHA-256",
                "encoding": "TPAA/v1 length-prefixed typed encoding with domain-separated tags",
                "H(ID)": {
                    "formula": "SHA-256(encode('HID', ID))",
                    "input": "ID from decrypted CR; value is not returned",
                    "result": "computed and used to verify AF; withheld to prevent identity guessing",
                },
                "crDigest": {
                    "formula": "SHA-256(encode('json', canonical_json(unsigned decrypted CR)))",
                    "result": app["crDigest"],
                },
                "AF": {
                    "formula": "h(ID) * APub * TPub * g^rBind mod p",
                    "resultHex": format(opened.af.af, "x"),
                },
            },
            "omitted": ["PII 原文", "生物特征原文", "身份哈希及随机开口"],
        }

    # ---- 进程内端口：phc-service 签发时取件 ----
    def opened_for_issue(self, app_id: str):
        app = self._get(app_id)
        opened = self._reopen(app)
        self._verify_evidence(opened, self.ctx.clock.now())
        return opened, app["crDigest"]

    def _verify_evidence(self, opened, now: str) -> None:
        policy = self.ctx.identity_policy
        if policy is None:
            if not self.ctx.test_adapter:
                raise RuntimeError("身份核验策略未配置")
            return
        v1.identity_evidence.verify(
            opened.identity_evidence, trusted_issuers=policy.trusted_issuers,
            min_assurance=policy.min_assurance, hid=opened.hid,
            user_sign_pk=opened.user_sign_pk, tp_nonce=opened.tp_nonce,
            request_id=opened.request_id, now=now)

    def owner_of(self, app_id: str) -> str:
        return self._get(app_id)["owner"]

    def mark(self, app_id: str, state: str) -> None:
        def _upd(d):
            d["apps"][app_id]["state"] = state
            return d
        self._get(app_id)
        self.ctx.store.update(_upd)

    def digest_of(self, app_id: str) -> str:
        return self._get(app_id)["crDigest"]

    # ------------------------------------------------------------------
    def _get(self, app_id: str) -> dict:
        app = self.ctx.store.load().get("apps", {}).get(app_id)
        if app is None:
            raise NotFound(f"申请不存在：{app_id}")
        return app

    def _reopen(self, app: dict):
        # 有效期按受理时刻判断：审核要花时间，不能让"排队太久"变成 CR 过期
        return v1.tp.tp_open_cr(tp_hsm=self.ctx.tp_hsm, cr_box=app["crBox"],
                                now=app["receivedAt"])

    @staticmethod
    def review_metadata(opened) -> dict:
        return {"pii": {key: _mask(value) for key, value in opened.pii.items()},
                "biFields": sorted(opened.bi.keys())}

    @staticmethod
    def has_review_metadata(metadata) -> bool:
        return (isinstance(metadata, dict)
                and isinstance(metadata.get("pii"), dict)
                and all(isinstance(key, str) and isinstance(value, str)
                        for key, value in metadata["pii"].items())
                and isinstance(metadata.get("biFields"), list)
                and all(isinstance(field, str) for field in metadata["biFields"]))


__all__ = ["IdentityIntake"]
