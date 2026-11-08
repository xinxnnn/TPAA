"""端到端（HTTP 层）：从「举报」到「全网停运」，全部走真实端点。

与 `tests/unit/test_trace_chain.py` 的分工：

    单测（领域层）  证明**规则**成立：未立案不许查、双人复核、级联不漏人
    本文件          证明**接缝**成立：路径参数、状态码、字段名、错误码映射

为什么非要再起一遍 HTTP：
    领域层全绿、线上照样出事，几乎都出在接缝上。这条链有三个特别脆的接缝 ——

      1  `/v1/dids/{did:path}` 会吞掉斜杠。DID 里带冒号、路径里带 `/trace`，
         路由顺序错一行，`GET /v1/dids/xxx/trace` 就会被解析成 did="xxx/trace"，
         报 404，看起来像"这个 DID 没登记"，排查要花一天。
      2  未立案必须回 **403** 而不是 400。合并了就等于把"越权尝试"降级成"手滑"，
         安全日志里再也捞不出来。
      3  DID 原样出现在路径里，中间任何一层做了 URL 规范化/转义，链子就断了。

前提：需要 fastapi + httpx。缺依赖时整组 SKIP，不伪装成通过。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import TraceChain, load_service  # noqa: E402

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except Exception:                                        # noqa: BLE001
    TestClient = None                                     # type: ignore[assignment]
    _HAVE_FASTAPI = False


def _skip() -> None:
    if not _HAVE_FASTAPI:
        from run_tests import Skipped

        raise Skipped("集成测试需要 fastapi + httpx（见 README 环境说明）")


# ---------------------------------------------------------------------------
# 夹具：一条链，六个端点
# ---------------------------------------------------------------------------


class Api:
    """把六个服务的 app 装到同一份 TraceChain 装配上。

    ★ 六个 app 共用同一批 ctx —— 也就是共用同一份账本、同一份注册表、同一个监管密钥。
      真实部署里它们是六个进程、靠 HTTP 互相调用；这里把"互相调用"换回进程内直连，
      但**入口仍然是 HTTP**，所以本文件要验的接缝（路由、状态码、字段）都是真的。
    """

    def __init__(self) -> None:
        self.c = TraceChain()
        self.clients: list[TestClient] = []

        self.did = self._app("did-service", self.c.did_ctx)
        self.sup = self._app("supervision-service", self.c.sup_ctx)
        self.coord = self._app("coordination", self.c.coord_ctx)
        self.policy = self._app("policy-service", self.c.policy_ctx)
        self.audit = self._app("audit-service", self.c.audit_ctx)
        self.life = self._app("lifecycle-service", self.c.life_ctx)

    def _app(self, service: str, ctx) -> "TestClient":
        app = load_service(service, "app").create_app(ctx=ctx)
        client = TestClient(app)
        self.clients.append(client)
        return client

    @property
    def hid_hex(self) -> str:
        return format(self.c.hid, "x").zfill(64)

    def close(self) -> None:
        for c in self.clients:
            c.close()
        self.c.close()


class api_env:
    def __init__(self) -> None:
        self.a: Api | None = None

    def __enter__(self) -> Api:
        self.a = Api()
        return self.a

    def __exit__(self, *exc) -> None:
        if self.a is not None:
            self.a.close()


def _register(a: Api, did: str, *, parent: str = "", ecid: str = "") -> dict:
    r = a.did.post("/v1/dids/register", json={
        "did": did, "identityHash": a.hid_hex, "parentDid": parent,
        "ecidRef": ecid, "confirmedByUser": bool(parent),
    })
    assert r.status_code == 200, r.text
    return r.json()


def _seed_via_http(a: Api) -> tuple[str, str]:
    """主 + 子两只，全部经 did-service 的 HTTP 登记。"""
    root_did, _ = a.c.issue_primary()
    ecid = a.c.g2_envelope()
    _register(a, root_did, ecid=ecid)
    sub_did, _ = a.c.derive_child(root_did)
    _register(a, sub_did, parent=root_did, ecid=ecid)
    return root_did, sub_did


def _report(a: Api, did: str) -> str:
    r = a.sup.post("/v1/cases", json={
        "subjectDid": did, "reporter": "victim-001",
        "allegation": "该子体批量骚扰用户", "evidenceRef": "ipfs://evidence-1",
    })
    assert r.status_code == 200, r.text
    return r.json()["caseId"]


def _file(a: Api, case_id: str) -> None:
    r = a.sup.post(f"/v1/cases/{case_id}/file", json={
        "reviewers": ["reviewer-a", "reviewer-b"], "note": "证据充分"})
    assert r.status_code == 200, r.text


def _answer_ticket(a: Api, ticket_id: str, sub_did: str) -> None:
    """AP 域内算出归属证明，再经跨域唯一通道答复。

    真实拓扑就是这样：计算发生在 AP 自己的域内（lifecycle-service 的用例），
    跨出去的那一步走工单 —— 而不是把 AP 的库直接连给 TP 看。
    """
    assist = load_service("lifecycle-service", "domain.usecases").AnswerAssistUseCase(
        a.c.life_ctx).execute(kind="lineage_proof", payload={"did": sub_did})
    r = a.coord.post(f"/v1/tickets/{ticket_id}/answer",
                     json={"responder": "AP", "answer": assist.answer})
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# 1. 六个服务都起得来
# ---------------------------------------------------------------------------


def test_every_service_reports_itself_healthy():
    _skip()
    with api_env() as a:
        for name, client in (
            ("did", a.did), ("supervision", a.sup), ("coordination", a.coord),
            ("policy", a.policy), ("audit", a.audit), ("lifecycle", a.life),
        ):
            r = client.get("/healthz")
            assert r.status_code == 200, (name, r.text)
            assert r.json()["status"] in ("ok", "degraded"), (name, r.json())


# ---------------------------------------------------------------------------
# 2. 路由接缝：{did:path} 不许吞掉 /trace
# ---------------------------------------------------------------------------


def test_did_subroutes_are_not_swallowed_by_path_param():
    """DID 里有冒号、后面还跟 `/trace` —— 路由顺序错一行就会 404。"""
    _skip()
    with api_env() as a:
        root_did, sub_did = _seed_via_http(a)

        trace = a.did.get(f"/v1/dids/{sub_did}/trace")
        assert trace.status_code == 200, trace.text
        body = trace.json()
        assert body["chain"] == [sub_did, root_did], body
        assert body["root"] == root_did
        assert body["depth"] == 1

        kids = a.did.get(f"/v1/dids/{root_did}/children")
        assert kids.status_code == 200, kids.text
        assert kids.json()["children"] == [sub_did]

        one = a.did.get(f"/v1/dids/{sub_did}")
        assert one.status_code == 200, one.text
        assert one.json()["parentDid"] == root_did


def test_resolve_never_returns_the_sealed_identity():
    """号码簿对外只给归属关系，不给 CSCID —— 拿到了也只是密文，但依然不该给。"""
    _skip()
    with api_env() as a:
        root_did, _ = _seed_via_http(a)
        body = a.did.get(f"/v1/dids/{root_did}").json()
        assert "cscid" not in body, body
        assert body["ecidRef"], "ECID 应当公开（它是定位串，不是身份）"


def test_unknown_did_is_404_not_500():
    _skip()
    with api_env() as a:
        r = a.did.get("/v1/dids/did:tpaa:nobody")
        assert r.status_code == 404, r.text


def test_duplicate_registration_is_409():
    _skip()
    with api_env() as a:
        root_did, _ = _seed_via_http(a)
        r = a.did.post("/v1/dids/register",
                       json={"did": root_did, "identityHash": a.hid_hex})
        assert r.status_code == 409, r.text


# ---------------------------------------------------------------------------
# 3. 闸门：未立案一律 403（不是 400）
# ---------------------------------------------------------------------------


def test_unfiled_investigation_returns_403():
    _skip()
    with api_env() as a:
        _, sub_did = _seed_via_http(a)
        case_id = _report(a, sub_did)

        r = a.sup.post(f"/v1/cases/{case_id}/investigate",
                       json={"requestedBy": "tp-officer"})
        assert r.status_code == 403, r.text
        assert "立案" in r.json()["message"], r.json()

        d = a.sup.post(f"/v1/cases/{case_id}/disclose")
        assert d.status_code == 403, d.text

        f = a.sup.post(f"/v1/cases/{case_id}/forensics",
                       json={"exportedBy": "tp-officer"})
        assert f.status_code == 403, f.text


def test_same_reviewer_twice_is_rejected_over_http():
    _skip()
    with api_env() as a:
        _, sub_did = _seed_via_http(a)
        case_id = _report(a, sub_did)

        r = a.sup.post(f"/v1/cases/{case_id}/file",
                       json={"reviewers": ["reviewer-a", "reviewer-a"]})
        assert r.status_code == 409, r.text

        assert a.sup.get(f"/v1/cases/{case_id}").json()["state"] == "reported"


def test_reveal_requires_a_case_ref_at_schema_layer():
    """没有案由的取用，连请求都不该成立 —— 422 挡在 pydantic 层。"""
    _skip()
    with api_env() as a:
        root_did, _ = _seed_via_http(a)
        r = a.did.post(f"/v1/dids/{root_did}/cscid",
                       json={"caseRef": "", "requestedBy": "x"})
        assert r.status_code == 422, r.text

        ok = a.did.post(f"/v1/dids/{root_did}/cscid",
                        json={"caseRef": "case-1", "requestedBy": "tp-officer"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["cscid"], "CSCID 不该为空"


# ---------------------------------------------------------------------------
# 4. 全链
# ---------------------------------------------------------------------------


def test_full_chain_over_http():
    _skip()
    with api_env() as a:
        root_did, sub_did = _seed_via_http(a)
        case_id = _report(a, sub_did)

        _file(a, case_id)

        inv = a.sup.post(f"/v1/cases/{case_id}/investigate",
                         json={"requestedBy": "tp-officer"})
        assert inv.status_code == 200, inv.text
        ticket_id = inv.json()["ticketId"]
        assert inv.json()["lineageChain"] == [sub_did, root_did]

        # 工单确实在跨域通道里挂着
        t = a.coord.get(f"/v1/tickets/{ticket_id}")
        assert t.json()["state"] == "pending", t.json()

        _answer_ticket(a, ticket_id, sub_did)

        pub = a.sup.post(f"/v1/cases/{case_id}/collect", json={"ticketId": ticket_id})
        assert pub.status_code == 200, pub.text
        # 取回答复**不推进状态**：案件仍在协查中，直到揭露为止。
        # 这一条值得单独钉住 —— 不然很容易有人把"收到答复"当成"案子查清了"。
        assert pub.json()["state"] == "investigating", pub.json()
        assert a.c.sup_ctx.cases.get(case_id).phc_json, "AP 的 PHC 没有留在案件里"

        dis = a.sup.post(f"/v1/cases/{case_id}/disclose")
        assert dis.status_code == 200, dis.text
        body = dis.json()
        assert int(body["identityHash"], 16) == a.c.hid, body
        assert body["verified"] is True, body.get("verifyNote")

        fx = a.sup.post(f"/v1/cases/{case_id}/forensics",
                        json={"exportedBy": "tp-officer"})
        assert fx.status_code == 200, fx.text
        fbody = fx.json()
        assert fbody["envelopeBytes"] > 0, "取证包里没有信封"
        assert fbody["chainVerified"] is True, fbody
        assert fbody["state"] == "sealed"

        # ---- 吊销与级联 ----
        rev = a.policy.post("/v1/revocations", json={
            "rootDid": root_did, "caseRef": case_id,
            "reason": "主体名下智能体用于骚扰", "issuedBy": "tp-officer",
        })
        assert rev.status_code == 200, rev.text
        rbody = rev.json()
        assert rbody["state"] == "notified", rbody
        assert set(rbody["revoked"]) == {root_did, sub_did}, rbody
        assert set(rbody["notified"]) == {root_did, sub_did}, rbody

        # 注册表侧：子体记为级联
        sub = a.did.get(f"/v1/dids/{sub_did}").json()
        assert sub["state"] == "revoked", sub
        assert sub["revokeSource"] == "cascade", sub

        # AP 侧：本机实例确实停了
        assert a.c.agent_ctx.agents.load_meta(sub_did).state.value == "frozen"
        assert a.c.agent_ctx.agents.load_meta(root_did).state.value == "frozen"

        # 审计链自洽
        v = a.audit.get("/v1/audit/verify")
        assert v.status_code == 200, v.text
        assert v.json()["ok"] is True, v.json()


def test_policy_revoke_requires_case_ref_and_reason():
    _skip()
    with api_env() as a:
        root_did, _ = _seed_via_http(a)
        r = a.policy.post("/v1/revocations", json={
            "rootDid": root_did, "caseRef": "", "reason": "随便"})
        assert r.status_code == 422, r.text

        r2 = a.policy.post("/v1/revocations", json={
            "rootDid": root_did, "caseRef": "case-1", "reason": ""})
        assert r2.status_code == 422, r2.text


# ---------------------------------------------------------------------------
# 5. 承接吊销：本机有的停，本机没有的如实报
# ---------------------------------------------------------------------------


def test_lifecycle_reports_not_local_instead_of_pretending():
    _skip()
    with api_env() as a:
        root_did, sub_did = _seed_via_http(a)
        stranger = "did:tpaa:somewhere-else"

        r = a.life.post("/v1/revocations", json={
            "rootDid": root_did, "revoked": [root_did, sub_did, stranger],
            "caseRef": "case-9", "reason": "上游广播",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body["stopped"]) == {root_did, sub_did}, body
        assert stranger in body["notLocal"], body

        # 再来一次：幂等，报到 already 里
        again = a.life.post("/v1/revocations", json={
            "rootDid": root_did, "revoked": [root_did],
            "caseRef": "case-9", "reason": "上游广播",
        }).json()
        assert again["stopped"] == [], again
        assert root_did in again["already"], again


def test_lifecycle_rejects_notice_without_case_ref():
    _skip()
    with api_env() as a:
        root_did, _ = _seed_via_http(a)
        r = a.life.post("/v1/revocations", json={
            "rootDid": root_did, "revoked": [root_did], "caseRef": ""})
        assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# 6. 审计：导出包不含密钥与身份明文
# ---------------------------------------------------------------------------


def test_audit_export_bundle_is_self_contained_but_harmless():
    _skip()
    with api_env() as a:
        root_did, sub_did = _seed_via_http(a)
        case_id = _report(a, sub_did)
        _file(a, case_id)

        r = a.audit.post("/v1/audit/export", json={
            "caseRef": case_id, "subjects": [root_did, sub_did]})
        assert r.status_code == 200, r.text
        body = r.json()

        kinds = {e["kind"] for e in body["entries"]}
        assert "case.filed" in kinds, kinds
        assert body["verification"]["ok"] is True, body["verification"]
        assert len(body["bundleDigest"]) == 64

        # 包里不该出现的东西
        text = r.text.lower()
        assert a.hid_hex not in text, "导出包里出现了 H(ID)"
        for word in ("trapdoor", "privatekey", "private_key", "cscid"):
            assert word not in text, f"导出包里出现了 {word}"


def test_audit_export_without_case_ref_is_rejected():
    _skip()
    with api_env() as a:
        r = a.audit.post("/v1/audit/export", json={"caseRef": ""})
        assert r.status_code == 400, r.text


# ---------------------------------------------------------------------------
# 7. 限流：没有案由的协查，配额只有十分之一
# ---------------------------------------------------------------------------


def test_case_less_tickets_are_throttled_fast():
    _skip()
    with api_env() as a:
        bodies = [{"requester": "TP", "responder": "AP", "kind": "lineage_proof",
                   "payload": {"did": f"did:tpaa:x{i}"}, "caseRef": ""}
                  for i in range(10)]
        codes = [a.coord.post("/v1/tickets", json=b).status_code for b in bodies]
        assert 429 in codes, codes
        assert codes.count(200) <= 2, codes      # 20 // 10 == 2


def test_private_material_on_the_wire_is_rejected():
    """跨域通道只该过公开材料 —— 密钥类字段在入口就被卡住。

    状态码是 **403** 而不是 400：这不是"你填错了"，是"这条通道不允许传这个"。
    两者混用，安全日志里就区分不出"有人夹带私钥"和"前端少传了一个字段"。
    """
    _skip()
    with api_env() as a:
        for payload in ({"trapdoor": "deadbeef"}, {"privateKey": "x"},
                        {"cscid": "123"}, {"nested": {"a": 1}}):
            r = a.coord.post("/v1/tickets", json={
                "requester": "TP", "responder": "AP", "kind": "lineage_proof",
                "payload": payload, "caseRef": "case-1"})
            assert r.status_code == 403, (payload, r.text)
            assert r.json()["code"] == 403, r.json()


def test_ticket_cannot_be_answered_by_the_asker():
    _skip()
    with api_env() as a:
        t = a.coord.post("/v1/tickets", json={
            "requester": "TP", "responder": "AP", "kind": "lineage_proof",
            "payload": {"did": "did:tpaa:abc"}, "caseRef": "case-1"}).json()

        r = a.coord.post(f"/v1/tickets/{t['ticketId']}/answer",
                         json={"responder": "TP", "answer": {"parentDid": ""}})
        assert r.status_code == 409, r.text
