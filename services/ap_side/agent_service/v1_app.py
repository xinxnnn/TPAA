"""agent-service 的 tpaa_v1 入口（D2 / D4），与 proto0 的 `app.py` 并存、互不共用 HSM。

    POST /v1/auth/challenge | login        AP 域登录（aud = tpaa:ap）
    GET  /v1/tpaa/keys                     AP 公钥包：签名公钥、变色龙公钥、加密公钥（**无陷门**，公开）
    POST /v1/tpaa/slots                    [user] 为自己的签名公钥分配 AP 陷门槽位
    POST /v1/tpaa/sessions                 [user] D1→D2：收 AR 密文（签名人须是登录用户），回 CMM 密文
    POST /v1/tpaa/sessions/{id}/build      [user] D3→D4：只能构建自己的会话，回 PAR 密文
    POST /v1/tpaa/assist                   [签名授权] R1 协查：TP 签名 + 两名 AP 认可的监管员签字

CMM 由 localstore 模块仓库生成：每个模块是一个功能类别，未下架的版本是可选实现。
模块摘要一律取自仓库（read 时核对 manifest），不信任用户在 PACI 里写的任何摘要。

★ 会话库里存的是 **AR 密文**，不存 r_ap：r_ap 要到构建时才在 HSM 里解开。
★ AP 记录（ApRecord）含 r_ap'。它永不出 AP（errata 限界 2），本服务没有任何端点返回它。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from fastapi import Body, FastAPI

import crypto.sdk
from services.shared.store import JsonStore
from services.shared.v1_http import (
    Conflict, Forbidden, NotFound, SystemClock, claim_request_id, hex_pk, install_errors,
)
from .domain.services.build import BuildPlan, assemble
from packages.tpaa_runtime.manifest import Capability, ToolDeclaration, build_manifest

v1 = crypto.sdk.v1


@dataclass
class AgentV1Context:
    ap_hsm: object
    modules: object             # localstore.ModuleRepo
    tp_sign_pk: object
    sup_pub: object
    domain2: str
    store: JsonStore
    tp_finalize_pk: object | None = None              # D6 状态公钥保留位
    clock: object = field(default_factory=SystemClock)
    supervisors: set = field(default_factory=set)   # AP 认可的监管员签名公钥（hex），部署注入
    tp_enc_pk: int | None = None                     # 协查应答封给 TP
    runtime_tp_hsm: object | None = None              # 仅本地 test-adapter 运行时装配
    runtime_agents: dict = field(default_factory=dict)


def build_context(*, ap_hsm, modules, tp_sign_pk, sup_pub, domain2: str, db_path: str,
                  clock=None, supervisors=(), tp_enc_pk: int | None = None,
                  runtime_tp_hsm=None) -> AgentV1Context:
    if getattr(ap_hsm, "domain", None) != "AP":
        raise RuntimeError("agent-service v1 需要 AP 域的 HSM")
    return AgentV1Context(ap_hsm=ap_hsm, modules=modules, tp_sign_pk=tp_sign_pk,
                          sup_pub=sup_pub, domain2=domain2, store=JsonStore(db_path),
                          clock=clock or SystemClock(), supervisors=set(supervisors),
                          tp_enc_pk=tp_enc_pk, runtime_tp_hsm=runtime_tp_hsm)


class AgentV1Desk:
    def __init__(self, ctx: AgentV1Context) -> None:
        self.ctx = ctx

    def session_artifact(self, sid: str, *, caller: str) -> dict:
        session = self.ctx.store.load().get("sessions", {}).get(sid)
        if session is None:
            raise NotFound(f"会话不存在：{sid}")
        if session["owner"] != caller:
            raise Forbidden("只能查看自己的 AP 会话")
        return {"sessionId": sid, "applicationId": session.get("applicationId"),
                "arEnvelope": session["arBox"], "cmmVersion": session["cmmVersion"]}

    # ---- CMM ----
    def catalog(self) -> dict:
        root = self.ctx.modules.layout.modules
        cats = []
        if root.exists():
            for d in sorted(p for p in root.iterdir() if p.is_dir()):
                opts = [v for v in self.ctx.modules.versions(d.name)
                        if not self.ctx.modules.get_entry(d.name, v).revoked]
                if opts:
                    cats.append({"id": d.name, "options": opts})
        body = {"categories": cats}
        # 版本号 = 目录内容的摘要：目录一变版本就变，D3 绑定的就是"用户看到的那一版"
        return {"version": "cmm-" + _digest(body)[:16], **body}

    def resolve(self, selection: list[dict]) -> list[tuple[str, str, str]]:
        out = []
        for item in selection:
            mid, ver = item["moduleId"], item["version"]
            try:
                e = self.ctx.modules.get_entry(mid, ver)
            except FileNotFoundError as exc:
                raise v1.ProtocolError(f"所选模块不存在：{mid}@{ver}") from exc
            if e.revoked:
                raise v1.ProtocolError(f"所选模块已下架：{mid}@{ver}")
            bad = self.ctx.modules.verify(mid, ver)
            if bad:
                raise Forbidden(f"模块仓库里的 {mid}@{ver} 被改动过：{bad}")
            out.append((mid, ver, e.digest))
        return out

    # ---- D2 ----
    def open_session(self, ar_box: dict, *, caller: str, application_id: str) -> dict:
        """D2。applicationId 在开会话时一次绑定，之后 D4 声明用的就是它。

        ⚠️ AP 无法独立核验这个号（它是 TP 的申请号，AR / TPAC 里都没有）。
        真正的锚点是 AFRef：D6 会把声明的 AFRef 与自己 G3 记录的 AF 对齐，
        号填错只会让 D6 拒绝，换不到另一份凭证上去。
        """
        c = self.ctx
        now = c.clock.now()
        if not application_id:
            raise v1.ProtocolError("开会话必须带 applicationId（D4 声明要绑定它）")
        sess = v1.ap.ap_open_ar(ap_hsm=c.ap_hsm, ar_box=ar_box, tp_sign_pk=c.tp_sign_pk, now=now)
        if sess.owner != caller:
            raise Forbidden("AR 的签名人与登录用户不一致")
        claim_request_id(c.store, "AR", sess.request_id, now)
        cmm = self.catalog()
        sid = "ses-" + secrets.token_hex(12)

        def _put(d):
            d.setdefault("sessions", {})[sid] = {
                "arBox": ar_box, "openedAt": now, "cmmVersion": cmm["version"], "built": False,
                "owner": sess.owner, "applicationId": application_id}
            return d

        c.store.update(_put)
        return {"sessionId": sid, "cmm": v1.ap.ap_send_cmm(session=sess, cmm=cmm),
                "event": {"stage": "D2", "status": "complete", "artifacts": {
                    "cmmVersion": cmm["version"],
                    "moduleCount": sum(len(x["options"]) for x in cmm["categories"])}}}

    # ---- D4 ----
    def build(self, sid: str, paci_box: dict, *, caller: str) -> dict:
        c = self.ctx
        state = c.store.load()
        s = state.get("sessions", {}).get(sid)
        if s is None:
            raise NotFound(f"会话不存在：{sid}")
        if s["owner"] != caller:
            raise Forbidden("只能构建自己的会话")
        request_digest = v1.json_digest(paci_box)
        legacy_record_id = None
        if s["built"]:
            if s.get("buildRequestDigest") == request_digest:
                if isinstance(s.get("buildResult"), dict):
                    return s["buildResult"]
                raise Conflict("该会话的 D4 响应缓存缺失，无法安全重放")
            if "buildRequestDigest" not in s:
                legacy_record_id = self._legacy_build_record(
                    state, s, sid, paci_box, caller)
            else:
                raise Conflict("该会话已使用不同 PACI 构建，不能替换已签署配置")
        if self.catalog()["version"] != s["cmmVersion"]:
            raise Conflict("会话期间模块目录发生了变化，请重新发起申请")
        application_id = s.get("applicationId") or ""
        if not application_id:
            raise Conflict("会话没有绑定 applicationId（D2 之前的旧会话），请重新发起申请")
        sess = v1.ap.ap_open_ar(ap_hsm=c.ap_hsm, ar_box=s["arBox"], tp_sign_pk=c.tp_sign_pk,
                                now=s["openedAt"])
        # A legacy recovery creates a fresh D4 record; the original is retained for audit.
        rid = "rec-" + secrets.token_hex(8)
        par, rec = v1.ap.ap_build(ap_hsm=c.ap_hsm, session=sess, paci_box=paci_box,
                                  cmm_version=s["cmmVersion"], resolve=self.resolve,
                                  sup_pub=c.sup_pub, domain2=c.domain2, now=c.clock.now(),
                                  application_id=application_id, record_id=rid)
        key = f"{format(rec.hid, 'x')}:{rec.cmi}"
        result = {"sessionId": sid, "par": par, "recordId": rid,
                  "event": {"stage": "D4", "status": "complete", "artifacts": {
                      "recordId": rid, "cmi": rec.cmi,
                      "modules": [{"moduleId": m, "version": ver, "digest": digest}
                                  for m, ver, digest in rec.modules],
                      "moduleCount": len(rec.modules),
                      "cmiAlgorithm": "CMI=HCGen(CMC,H(ID))",
                      "cmiInputOrder": "CMM category order; order is significant"}}}
        if legacy_record_id is not None:
            result["event"]["artifacts"]["recoveredFromRecordId"] = legacy_record_id
        committed_result = {}

        def _put(d):
            current = d["sessions"][sid]
            if current["built"]:
                if current.get("buildRequestDigest") == request_digest:
                    if isinstance(current.get("buildResult"), dict):
                        committed_result["value"] = current["buildResult"]
                        return d
                    raise Conflict("该会话的 D4 响应缓存缺失，无法安全重放")
                if "buildRequestDigest" not in current:
                    if legacy_record_id is None:
                        raise Conflict("旧版 D4 状态无法安全恢复")
                    if (d.get("byHidCmi", {}).get(key) != legacy_record_id
                            or legacy_record_id in d.get("publications", {})):
                        raise Conflict("旧版 D4 记录状态已变化，不能安全恢复")
                    d.setdefault("records", {})[rid] = v1.records.dump(rec)
                    d["byHidCmi"][key] = rid
                    current["buildRequestDigest"] = request_digest
                    current["buildResult"] = result
                    current["recoveredFromRecordId"] = legacy_record_id
                    committed_result["value"] = result
                    return d
                raise Conflict("该会话已使用不同 PACI 构建，不能替换已签署配置")
            if key in d.setdefault("byHidCmi", {}) and d["byHidCmi"][key] != legacy_record_id:
                raise Conflict("同一身份已有同一配置的 PA（D2 查重）")
            d.setdefault("records", {})[rid] = v1.records.dump(rec)
            d["byHidCmi"][key] = rid
            current["built"] = True
            current["buildRequestDigest"] = request_digest
            current["buildResult"] = result
            committed_result["value"] = result
            return d

        c.store.update(_put)
        return committed_result["value"]

    def _legacy_build_record(self, state: dict, session: dict, sid: str,
                             paci_box: dict, caller: str) -> str:
        c = self.ctx
        application_id = session.get("applicationId") or ""
        if not application_id or self.catalog()["version"] != session["cmmVersion"]:
            raise Conflict("旧版 D4 会话已过期，不能安全恢复")
        paci = c.ap_hsm.pke_open(paci_box, tag="PACI")
        if paci.get("cmmVersion") != session["cmmVersion"]:
            raise Conflict("旧版 D4 恢复必须使用原 CMM 版本和配置")
        ap_session = v1.ap.ap_open_ar(ap_hsm=c.ap_hsm, ar_box=session["arBox"],
                                      tp_sign_pk=c.tp_sign_pk, now=session["openedAt"])
        modules = self.resolve(paci.get("selection", []))
        cmi = v1.hcgen(modules, ap_session.hid)
        key = f"{format(ap_session.hid, 'x')}:{cmi}"
        record_id = state.get("byHidCmi", {}).get(key)
        raw_record = state.get("records", {}).get(record_id)
        if not record_id or raw_record is None:
            raise Conflict("旧版 D4 没有可恢复的原配置记录")
        record = v1.records.load(raw_record)
        statement = v1.ap.check_d4_statement(record.statement, ap_sign_pk=c.ap_hsm.pubkey())
        if (record.owner != caller or record.cmi != cmi or record.modules != modules
                or statement.get("applicationId") != application_id
                or statement.get("recordId") != record_id
                or state.get("publications", {}).get(record_id)):
            raise Conflict("旧版 D4 恢复请求与原用户、申请或配置不一致")
        if session.get("applicationId") != application_id or session.get("owner") != caller:
            raise Conflict("旧版 D4 会话归属不一致，不能恢复")
        return record_id

    def publish(self, record_id: str, receipt: dict, *, caller: str) -> dict:
        c = self.ctx
        raw = c.store.load().get("records", {}).get(record_id)
        if raw is None:
            raise NotFound(f"D4 记录不存在：{record_id}")
        rec = v1.records.load(raw)
        if rec.owner != caller:
            raise Forbidden("只能发布自己的智能体")
        if rec.owner != receipt.get("owner") or receipt.get("did", "") == "":
            raise Forbidden("D6 接受回执归属不匹配")
        if receipt.get("applicationId", "") == "":
            raise v1.ProtocolError("D6 接受回执缺少 applicationId")
        statement = dict(receipt.get("finalizationAttestation") or {})
        tp_sig = statement.pop("sig", "")
        if c.tp_sign_pk is None:
            raise Forbidden("AP 未配置 TP 签名公钥，不能验证 D6 最终化声明")
        v1.check_sig(c.tp_sign_pk, tp_sig, "FinalizationAttestation",
                     v1.json_digest(statement), what="TP D6 完成声明")
        for field in ("applicationId", "owner", "userSignPk", "did", "phcDigest", "cmi"):
            if statement.get(field) != receipt.get(field):
                raise Forbidden(f"钱包回执与 TP 最终化声明的 {field} 不一致")
        upk = v1.pk_from_hex(receipt["userSignPk"])
        if v1.owner_of(upk) != rec.owner:
            raise Forbidden("发布回执中的用户公钥不属于该 D4 记录")
        if receipt["owner"] != rec.owner or receipt["cmi"] != rec.cmi:
            raise Forbidden("回执与 AP 的 D4 记录不一致")
        if receipt["modulesDigest"] != v1.json_digest(
                [{"moduleId": m, "version": ver, "digest": digest}
                 for m, ver, digest in rec.modules]):
            raise Forbidden("回执模块摘要与 D4 记录不一致")
        state = c.store.load()
        published = state.get("publications", {}).get(record_id)
        if published is not None:
            return published
        module_bytes = [(m, ver, c.modules.read_file(m, ver, "engine.py"))
                        for m, ver, _ in rec.modules]
        plan = assemble(did=receipt["did"], agent_type="personal-agent", parent_did="",
                        modules=module_bytes, cmi=rec.cmi, layer_chains=[], ecid="",
                        version=1)
        build_digest = plan.build_digest()
        capabilities, tools = self._runtime_contract(rec.modules)
        manifest = build_manifest(
            did=receipt["did"], phc_digest=receipt["phcDigest"], issuer="tp.example",
            af_ref=v1.af_ref(rec.af.af), modules=rec.modules,
            capabilities=capabilities, tools=tools, dependencies=[],
            created_at=c.clock.now(), cmi=rec.cmi,
            policy={"denyUnknownTools": True})
        manifest.build_digest = build_digest
        manifest.validate()
        publication = {
            "recordId": record_id, "owner": rec.owner, "did": receipt["did"],
            "phcDigest": receipt["phcDigest"], "cmi": rec.cmi,
            "modules": [{"moduleId": m, "version": ver, "digest": digest}
                        for m, ver, digest in rec.modules],
            "buildDigest": build_digest, "manifest": manifest.to_json(),
            "files": {k: v.decode("utf-8", errors="strict") for k, v in plan.files.items()},
            "status": "ACTIVE", "publishedAt": c.clock.now(),
        }
        proof_body = {
            "kind": "tpaa/ag2-publication", "recordId": record_id, "owner": rec.owner,
            "did": receipt["did"], "phcDigest": receipt["phcDigest"], "cmi": rec.cmi,
            "modulesDigest": v1.json_digest(publication["modules"]),
            "buildDigest": build_digest, "manifestDigest": manifest.digest(),
            "publishedAt": publication["publishedAt"],
        }
        publication["proof"] = {"body": proof_body,
                                "sig": v1.sign(c.ap_hsm, "AG2Publication", v1.json_digest(proof_body))}
        def _put(d):
            existing = d.setdefault("publications", {}).get(record_id)
            if existing is not None:
                return d
            d["publications"][record_id] = publication
            return d
        c.store.update(_put)
        return publication

    @staticmethod
    def _runtime_contract(modules):
        from packages.tpaa_runtime.manifest import Capability, ToolDeclaration

        supported = {
            "summarize": (
                "对文本进行确定性截断摘要",
                ToolDeclaration("summarize.run", "summarize", "确定性文本摘要",
                                allowed_operations=("run",)),
            ),
            "translate": (
                "本地演示翻译占位能力（原样返回输入）",
                ToolDeclaration("translate.run", "translate", "本地演示文本处理",
                                allowed_operations=("run",)),
            ),
        }
        capabilities, tools = [], []
        for module_id, version, _ in modules:
            entry = supported.get(module_id)
            if entry is None:
                capabilities.append(Capability(
                    module_id, version, f"已批准模块 {module_id}@{version}；未声明可执行工具"))
            else:
                purpose, tool_declaration = entry
                capabilities.append(Capability(module_id, version, purpose))
                tools.append(tool_declaration)
        return capabilities, tools

    def start_runtime(self, record_id: str, *, did: str, phc_doc: dict, caller: str) -> dict:
        c = self.ctx
        if c.runtime_tp_hsm is None:
            raise Forbidden("此部署未配置本地 test-adapter runtime 装配器")
        publication = self.publication(record_id, caller=caller)
        proof = publication.get("proof") or {}
        proof_body = dict(proof.get("body") or {})
        signature = proof.get("sig", "")
        v1.check_sig(c.ap_hsm.pubkey(), signature, "AG2Publication",
                     v1.json_digest(proof_body), what="AP 发布证明")
        expected = {
            "kind": "tpaa/ag2-publication", "recordId": record_id, "owner": caller,
            "did": publication["did"], "phcDigest": publication["phcDigest"],
            "cmi": publication["cmi"], "modulesDigest": v1.json_digest(publication["modules"]),
            "buildDigest": publication["buildDigest"],
            "manifestDigest": publication["manifest"]["audit"]["manifestDigest"],
            "publishedAt": publication["publishedAt"],
        }
        if proof_body != expected or did != publication["did"]:
            raise Forbidden("AP 发布证明与申请人凭证或发布记录不一致")
        phc = v1.from_jsonld(phc_doc)
        if v1.phc_digest(phc) != publication["phcDigest"]:
            raise Forbidden("最终 PHC 摘要与 AP 发布记录不一致")
        errors = v1.verify_public(phc, tp_pk=c.tp_sign_pk, ap_pk=c.ap_hsm.pubkey())
        if errors:
            raise Forbidden("最终 PHC 公开校验失败：" + "；".join(errors))

        raw = c.store.load().get("records", {}).get(record_id)
        if raw is None:
            raise NotFound(f"D4 记录不存在：{record_id}")
        rec = v1.records.load(raw)
        if rec.owner != caller or rec.cmi != publication["cmi"]:
            raise Forbidden("运行请求与 AP D4 记录不匹配")
        modules = [(m, ver, c.modules.read_file(m, ver, "engine.py"))
                   for m, ver, _ in rec.modules]
        plan = assemble(did=did, agent_type="personal-agent", parent_did="",
                        modules=modules, cmi=rec.cmi, layer_chains=[], ecid="", version=1)
        if plan.build_digest() != publication["buildDigest"]:
            raise Forbidden("AP 重算的确定性构建摘要与发布证明不一致")
        if {k: v.decode("utf-8", errors="strict") for k, v in plan.files.items()} != publication["files"]:
            raise Forbidden("发布文件与 AP 重算的确定性构建不一致")

        from packages.tpaa_runtime.manifest import build_manifest
        from packages.tpaa_runtime.runtime import (
            LOCAL_TEST_SKILLS, GuardLog, build_agent,
        )
        from packages.tpaa_runtime.sandbox import ToolGateway
        from packages.tpaa_runtime.trust import StatusRegistry, TrustContext, start_runtime
        from ag2.testing import TestConfig

        capabilities, tools = self._runtime_contract(rec.modules)
        if {module_id for module_id, _, _ in rec.modules} - {"summarize", "translate"}:
            raise Forbidden("本地 AG2 test-adapter 尚未实现所选模块的执行连接器")
        manifest = build_manifest(
            did=did, phc_digest=publication["phcDigest"], issuer="tp.example",
            af_ref=v1.af_ref(rec.af.af), modules=rec.modules,
            capabilities=capabilities, tools=tools, dependencies=[],
            created_at=publication["manifest"]["audit"]["createdAt"], cmi=rec.cmi,
            policy={"denyUnknownTools": True})
        manifest.build_digest = publication["buildDigest"]
        manifest.validate()
        if manifest.to_json() != publication["manifest"]:
            raise Forbidden("AP 发布 manifest 与重新构造结果不一致")
        trust = TrustContext(tp_pk=c.tp_sign_pk, ap_pk=c.ap_hsm.pubkey(),
                             status=StatusRegistry(), clock=c.clock.now)
        identity = start_runtime(did=did, phc_doc=phc_doc, manifest=manifest,
                                 tp_hsm=c.runtime_tp_hsm, ap_hsm=c.ap_hsm,
                                 ap_record=rec, trust=trust)
        handlers = {
            "summarize.run": lambda args: {"text": args["text"][:80]},
            "translate.run": lambda args: {
                "text": args["text"], "language": args["language"],
                "note": "test-adapter 原样返回，不执行真实翻译",
            },
        }
        gateway = ToolGateway(manifest, handlers=handlers)
        guard_log = GuardLog()
        agent = build_agent(
            name="tpaa-" + record_id[-12:], role="本地 test-adapter AG2 Agent",
            identity=identity, gateway=gateway, trust=trust, catalog=LOCAL_TEST_SKILLS,
            config=TestConfig("本地固定测试配置；未连接外部模型"),
            guard_log=guard_log)
        runtime_id = "runtime-" + secrets.token_hex(10)
        c.runtime_agents[runtime_id] = {"agent": agent, "identity": identity,
                                       "gateway": gateway, "trust": trust,
                                       "guardLog": guard_log}
        return {"runtimeId": runtime_id, "did": did,
                "buildDigest": publication["buildDigest"],
                "manifestDigest": manifest.digest(),
                "verifiedTools": [item.id for item in manifest.tools],
                "status": "agent_constructed", "model": "ag2.testing.TestConfig"}

    def publication(self, record_id: str, *, caller: str) -> dict:
        p = self.ctx.store.load().get("publications", {}).get(record_id)
        if p is None:
            raise NotFound(f"发布记录不存在：{record_id}")
        if p["owner"] != caller:
            raise Forbidden("只能读取自己的发布记录")
        return p

    def assist(self, req: dict) -> dict:
        """验 TP 签名 + AP 自己名录里两名不同监管员的立案签字 → 交回封装后的 s_ap。

        ★ 不靠令牌：这条请求的授权完全来自它自己携带的签名。
          TP 运维就算拿到 AP 的登录令牌，没有两名监管员的私钥也签不出这份请求。
        """
        c = self.ctx
        if not c.supervisors or c.tp_enc_pk is None:
            raise Forbidden("本 AP 未配置监管员名录 / TP 加密公钥，不接受协查")
        now = c.clock.now()
        af = v1.case.ap_check_assist(req, tp_sign_pk=c.tp_sign_pk, supervisors=c.supervisors,
                                     now=now)
        if not any(v1.records.load(r).af.af == af
                   for r in c.store.load().get("records", {}).values()):
            raise NotFound("该 AF 不是本 AP 签发的凭证")
        claim_request_id(c.store, "ASSIST", req["requestId"], now)
        s_ap = v1.ap.ap_assist(ap_hsm=c.ap_hsm, af=af, case_ok=True)

        def _log(d):
            d.setdefault("assistLog", []).append(
                {"requestId": req["requestId"], "caseId": req["caseId"], "did": req["did"][:48],
                 "approvers": sorted(a["signPk"][:16] for a in req["approvals"]), "at": now})
            return d

        c.store.update(_log)
        return {"answer": v1.case.ap_seal_answer(tp_enc_pk=c.tp_enc_pk,
                                                 request_id=req["requestId"], s_ap=s_ap)}


def _digest(obj) -> str:
    import hashlib
    import json
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def create_app(*, ctx: AgentV1Context, auth) -> FastAPI:
    """auth：AP 域的 AuthIssuer（aud = "tpaa:ap"）。TP 域的令牌在这里一律无效。"""
    from services.shared.v1_auth import install_auth_routes

    app = FastAPI(title="agent-service (tpaa_v1)", version="1.0.0")
    app.state.domain = "ap-side"
    app.state.ctx = ctx
    app.state.desk = desk = AgentV1Desk(ctx)
    install_errors(app)
    install_auth_routes(app, auth)
    guard = auth.verifier()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "agent-service", "profile": "tpaa_v1"}

    @app.get("/v1/tpaa/keys")
    def keys():
        h = ctx.ap_hsm
        return {"signPk": hex_pk(h.pubkey()),
                "chameleonCpk": crypto.sdk.ser_point(h.chameleon_cpk()).hex(),
                "encPub": format(h.enc_pub(), "x")}

    @app.post("/v1/tpaa/slots")
    def slots(userSignPk: str = Body(..., embed=True), who: dict = guard.require("user")):
        owner = v1.owner_of(v1.pk_from_hex(userSignPk))
        if owner != who["sub"]:
            raise Forbidden("只能为自己的签名公钥申请槽位")
        nonce, a_pub = ctx.ap_hsm.allocate_slot(owner)
        return {"nonce": nonce, "pub": format(a_pub, "x")}

    @app.post("/v1/tpaa/sessions")
    def sessions(ar: dict = Body(...), applicationId: str = Body(""),
                 who: dict = guard.require("user")):
        return desk.open_session(ar, caller=who["sub"], application_id=applicationId)

    @app.get("/v1/tpaa/sessions/{sid}")
    def session_artifact(sid: str, who: dict = guard.require("user")):
        return desk.session_artifact(sid, caller=who["sub"])

    @app.post("/v1/tpaa/sessions/{sid}/build")
    def build(sid: str, paci: dict = Body(..., embed=True), who: dict = guard.require("user")):
        return desk.build(sid, paci, caller=who["sub"])

    @app.post("/v1/tpaa/assist")
    def assist(req: dict = Body(..., embed=True)):
        return desk.assist(req)

    @app.post("/v1/tpaa/records/{record_id}/publish")
    def publish(record_id: str, receipt: dict = Body(..., embed=True),
                who: dict = guard.require("user")):
        return desk.publish(record_id, receipt, caller=who["sub"])

    @app.get("/v1/tpaa/publications/{record_id}")
    def publication(record_id: str, who: dict = guard.require("user")):
        return desk.publication(record_id, caller=who["sub"])

    @app.post("/v1/tpaa/publications/{record_id}/runtime")
    def start_runtime(record_id: str, body: dict = Body(...),
                      who: dict = guard.require("user")):
        return desk.start_runtime(record_id, did=body.get("did", ""),
                                  phc_doc=body.get("phc", {}), caller=who["sub"])

    return app


__all__ = ["AgentV1Context", "AgentV1Desk", "build_context", "create_app"]
