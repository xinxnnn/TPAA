"""gateway 的 HTTP 集成：把"换适配器即可分区部署"这句话跑一遍。

★ 这个文件存在的理由：

    README 与 ARCHITECTURE 里一直写着"进程内适配器换成 HTTP 客户端即可分区部署，
    domain 一行不用改"。它之前只是一句**声明**，从来没被执行过。
    声明没人验证，就会在第一次真正需要分区时才发现装配不上 ——
    而那时候改的就不是适配器，而是 domain 了。

    所以这里做的是同一件事的两次：
      一次走 LocalChannel（进程内函数调用）
      一次走 HttpChannel（真起一个 coordination 的 HTTP 服务，真发请求）
    两次用的是**同一个用例、同一份领域规则**，断言结果一致。

★ 它没有测 mTLS。分区部署真正的难点在证书与身份认证，那部分没做，
  在 README 的"真实缺口"里记着，不假装这里覆盖了。
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
# 夹具
# ---------------------------------------------------------------------------


class Rig:
    """一条链 + 一个真起在 HTTP 上的 coordination + 两个形态的 gateway。"""

    def __init__(self) -> None:
        self.c = TraceChain()
        self.root, self.sub = self.c.seed()

        coord_app = load_service("coordination", "app").create_app(ctx=self.c.coord_ctx)
        self.coord = TestClient(coord_app)

        # ★ 同一个 coordination，两种访问方式
        wiring = load_service("gateway", "infra.wiring")
        self.local_gw_ctx = wiring.build_dev_context(
            coord_ctx=self.c.coord_ctx, lifecycle_ctx=self.c.life_ctx,
            audit_ctx=self.c.audit_ctx, clock=self.c.t_coord)
        self.http_gw_ctx = wiring.build_http_context(
            base_url="http://testserver", lifecycle_ctx=self.c.life_ctx,
            audit_ctx=self.c.audit_ctx, clock=self.c.t_coord, client=self.coord)

        self.local_app = TestClient(
            load_service("gateway", "app").create_app(ctx=self.local_gw_ctx))
        self.http_app = TestClient(
            load_service("gateway", "app").create_app(ctx=self.http_gw_ctx))

    def open_ticket(self, kind="lineage_proof", did=None, case="case-1"):
        r = self.coord.post("/v1/tickets", json={
            "requester": "TP", "responder": "AP", "kind": kind,
            "payload": {"did": did or self.sub}, "caseRef": case})
        assert r.status_code == 200, r.text
        return r.json()["ticketId"]

    def close(self) -> None:
        self.c.close()


class rig_env:
    def __enter__(self) -> Rig:
        self.r = Rig()
        return self.r

    def __exit__(self, *exc) -> None:
        self.r.close()


# ---------------------------------------------------------------------------
# 1. 两种适配器，同一个 domain
# ---------------------------------------------------------------------------


def test_http_channel_matches_local_channel():
    """★ 核心：同一份领域规则，走 HTTP 与走进程内，结果一致。

    两张单子分开处理：两个 gateway 共用同一个 coordination，
    一次 drain 会把两张都吃掉，那就分不出是谁答的了。
    """
    _skip()
    with rig_env() as r:
        tid_local = r.open_ticket(case="case-local")
        a = r.local_app.post("/v1/outbox/drain", json={})
        assert a.status_code == 200, a.text
        assert a.json()["answered"] == 1, a.json()

        tid_http = r.open_ticket(case="case-http")
        b = r.http_app.post("/v1/outbox/drain", json={})
        assert b.status_code == 200, b.text
        assert b.json()["answered"] == 1, b.json()

        for tid in (tid_local, tid_http):
            got = r.coord.get(f"/v1/tickets/{tid}").json()
            assert got["state"] == "answered", got
            assert got["answer"]["status"] == "ok"
            assert got["answer"]["parentDid"] == r.root
            assert got["answer"]["phcJson"]


def test_http_channel_sees_the_same_inbox():
    """收件箱跨进程一致：HTTP 拉到的单子，就是通道里待答的那些。"""
    _skip()
    with rig_env() as r:
        tids = [r.open_ticket(case=f"case-{i}") for i in range(3)]
        pend = r.http_app.get("/v1/outbox/pending")
        assert pend.status_code == 200, pend.text
        assert pend.json()["count"] == 3, pend.json()
        assert set(pend.json()["tickets"]) == set(tids)


def test_pending_is_read_only():
    """看积压不该有写副作用 —— 否则 TP 反复列就能把单子刷没。"""
    _skip()
    with rig_env() as r:
        r.open_ticket()
        before = r.coord.get("/v1/tickets", params={"responder": "AP"}).json()
        r.http_app.get("/v1/outbox/pending")
        r.http_app.get("/v1/outbox/pending")
        after = r.coord.get("/v1/tickets", params={"responder": "AP"}).json()
        assert before == after


def test_drain_twice_does_not_reanswer():
    """同一张单子不会被答两次 —— 重复答复会让取证无法确定哪份是真的。"""
    _skip()
    with rig_env() as r:
        tid = r.open_ticket()
        assert r.http_app.post("/v1/outbox/drain", json={}).json()["answered"] == 1
        second = r.http_app.post("/v1/outbox/drain", json={})
        assert second.json()["polled"] == 0, second.json()
        assert r.coord.get(f"/v1/tickets/{tid}").json()["state"] == "answered"


# ---------------------------------------------------------------------------
# 2. 端点语义
# ---------------------------------------------------------------------------


def test_healthz_reports_identity_and_capability():
    """健康检查要说清"我是谁、我答应答什么" —— 这是边界服务的自我介绍。"""
    _skip()
    with rig_env() as r:
        h = r.http_app.get("/healthz").json()
        assert h["service"] == "gateway" and h["domain"] == "ap-side"
        assert h["selfId"] == "AP"
        assert h["allowedKinds"] == ["lineage_proof"]
        assert h["problems"] == []


def test_unsupported_kind_is_refused_over_http():
    """类别不答应 → 工单 answered 且 status=refused，而不是挂到过期。"""
    _skip()
    with rig_env() as r:
        tid = r.open_ticket(kind="give_me_trapdoor")
        out = r.http_app.post("/v1/outbox/drain", json={}).json()
        assert out["answered"] == 1
        got = r.coord.get(f"/v1/tickets/{tid}").json()
        assert got["answer"]["status"] == "refused"
        assert "give_me_trapdoor" in got["answer"]["reason"]


def test_not_local_does_not_leak_paths():
    """不在本机就说不在，且不把本机路径带出网。"""
    _skip()
    with rig_env() as r:
        tid = r.open_ticket(did="did:tpaa:sub:999999")
        r.http_app.post("/v1/outbox/drain", json={})
        answer = r.coord.get(f"/v1/tickets/{tid}").json()["answer"]
        assert answer["status"] == "not_local"
        assert answer["reason"] == "该实例不在本节点"
        assert "/" not in answer["reason"]


def test_revocation_requires_case_ref_at_the_edge():
    """吊销广播缺案由 → 拒，且不落到 lifecycle。

    两级拦截，语义不同：
        空字符串  pydantic 层 422（根本没进领域）
        空白字符  BadNotice 400（进了领域，被"案由必填"这道边界校验拦下）
    第二种才是真正要测的 —— 它是 gateway 在网络边界上自己做的那一次判断。
    """
    _skip()
    with rig_env() as r:
        bad = r.http_app.post("/v1/revocations",
                              json={"rootDid": r.root, "revoked": [], "caseRef": ""})
        assert bad.status_code == 422, bad.text

        resp = r.http_app.post("/v1/revocations", json={
            "rootDid": r.root, "revoked": [], "caseRef": " "})
        assert resp.status_code == 400, resp.text
        assert "案由" in resp.json()["message"]

        # 且本地实例没被停掉
        meta = r.c.life_ctx.store.load_meta(r.root)
        assert meta.state.value not in ("frozen", "revoked"), meta.state.value


def test_revocation_is_accepted_and_stops_locally():
    """有案由的吊销 → 承接并真的停掉本地实例。"""
    _skip()
    with rig_env() as r:
        out = r.http_app.post("/v1/revocations", json={
            "rootDid": r.root, "revoked": [r.sub], "caseRef": "case-1"})
        assert out.status_code == 200, out.text
        j = out.json()
        assert j["accepted"] is True
        assert r.root in j["stopped"], j
        # 子体即便没点名，本地扫后代时也要补上
        assert r.sub in j["stopped"], j


def test_export_blocked_returns_403_and_writes_nothing():
    """出口卡口拦下 → 403，且通道上一个字节都没多。

    ★ 这是安全事件，不是业务拒绝 —— 所以是 403 而不是 409。
    """
    _skip()
    with rig_env() as r:
        tid = r.open_ticket()

        # 让 lifecycle 的回答里多出一个未登记的键
        class _Sneaky:
            def answer_assist(self, *, kind, payload):
                return {"did": payload.get("did", ""), "parentDid": "p",
                        "agentType": "sub", "state": "active",
                        "phcJson": "{}", "phcDigest": "d",
                        "internalNote": "/data/ap/agents/xxx"}

        r.http_gw_ctx.assist = _Sneaky()
        out = r.http_app.post("/v1/outbox/drain", json={})
        assert out.status_code == 200, out.text
        assert out.json()["blocked"] == [tid], out.json()

        got = r.coord.get(f"/v1/tickets/{tid}").json()
        assert got["state"] == "pending", got        # 什么都没送出去
        assert got["answer"] == {}


def test_dead_channel_refuses_to_start():
    """通道不通 → 起不来。

    ★ 这是比"起来但 degraded"更好的行为：
      一个收不到件的 gateway 会安静地让所有单子过期，
      而健康检查是绿的（本机端口都在）。宁可起不来。
    """
    _skip()
    with rig_env() as r:
        try:
            load_service("gateway", "infra.wiring").build_http_context(
                base_url="http://127.0.0.1:9",      # 必然连不上
                lifecycle_ctx=r.c.life_ctx, audit_ctx=r.c.audit_ctx,
                client=None)
        except Exception as exc:                     # noqa: BLE001
            assert "跨域通道不可达" in str(exc), str(exc)
            return
        raise AssertionError("通道不通竟通过了启动自检")


def test_channel_dying_midrun_is_visible():
    """运行中通道挂了 → 回写失败要看得见，而不是"看起来都答了"。

    与上面那条互补：那条管"起不来"，这条管"跑着跑着断了"。
    """
    _skip()
    with rig_env() as r:
        tid = r.open_ticket()
        adapters = load_service("gateway", "infra.adapters")
        r.local_gw_ctx.channel = adapters.HttpChannel(base_url="http://127.0.0.1:9")

        out = r.local_app.post("/v1/outbox/drain", json={})
        # 拉取阶段就断线：整轮一个工单也没处理，必须 503，不能假装 200 空收件箱。
        assert out.status_code == 503, out.text
        assert "跨域通道不可达" in out.json()["message"]

        got = r.coord.get(f"/v1/tickets/{tid}").json()
        assert got["state"] == "pending", got


def test_channel_answer_failure_keeps_ticket_pending():
    """拉取成功但单张回写断线：200 + delivered=False，区别于整轮拉取失败。"""
    _skip()
    with rig_env() as r:
        tid = r.open_ticket()
        delegate = r.local_gw_ctx.channel

        class BrokenAnswer:
            def pull(self, **kwargs):
                return delegate.pull(**kwargs)

            def answer(self, **kwargs):
                raise ConnectionError("回写通道断开")

        r.local_gw_ctx.channel = BrokenAnswer()
        out = r.local_app.post("/v1/outbox/drain", json={})
        assert out.status_code == 200, out.text
        report = out.json()
        assert report["answered"] == 0
        assert report["items"] and report["items"][0]["delivered"] is False
        assert r.coord.get(f"/v1/tickets/{tid}").json()["state"] == "pending"


__all__ = [n for n in dir() if n.startswith("test_")]
