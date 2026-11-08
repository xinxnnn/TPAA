"""端到端：真起 HTTP，真走「申领 → 签发 → 落 localstore」。

为什么坚持起真 HTTP 而不是直接调用例：
    步骤 10 的目标不是"逻辑写完了"，而是"这条链路能跑"。
    而链路里最容易出事的恰好是**接缝**：请求字段名、错误码映射、
    确认令牌要在两次请求之间传递、落盘的东西下一次请求还能不能读到。
    这些只有真起 HTTP 才测得到。

前提：需要 fastapi + httpx（隔离 venv 已装）。缺依赖时整组跳过，
不伪装成通过 —— 那会让"没测"看起来像"测过了"。
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from harness import load_agent_service, load_agent_service_app  # noqa: E402

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except Exception:                                        # noqa: BLE001
    TestClient = None                                     # type: ignore[assignment]
    _HAVE_FASTAPI = False


_HID = "0x" + "11" * 32


def _skip() -> None:
    """缺依赖时**抛**出去，让运行器记一笔 SKIP。

    不用 `return`：那样调用方什么都看不出，一个写漏断言的测试
    会安静地变成"通过"。抛出来，至少统计里有一行 [SKIP]。
    """
    if not _HAVE_FASTAPI:
        from run_tests import Skipped

        raise Skipped("集成测试需要 fastapi + httpx（见 README 步骤 10）")


# ---------------------------------------------------------------------------
# 夹具
# ---------------------------------------------------------------------------


class Env:
    """一个装好模块、起好服务的最小环境。"""

    def __init__(self) -> None:
        from services.ipfs.storage_service.app import StorageService


        self.tmp = tempfile.TemporaryDirectory()
        self.storage = StorageService()
        self.clock = load_agent_service("infra.clock").FixedClock()
        app_mod = load_agent_service_app()
        self.app = app_mod.create_app(
            dev_store=self.tmp.name, storage=self.storage, clock=self.clock)
        self.client = TestClient(self.app)
        self.ctx = self.app.state.ctx
        self._publish_modules()

    def _publish_modules(self) -> None:
        self.ctx.modules.publish(
            "summarize", "1.0.0",
            {"engine.py": b"def run(text):\n    return text[:80]\n"},
            description="摘要")
        self.ctx.modules.publish(
            "translate", "1.0.0",
            {"engine.py": b"def run(text, lang):\n    return text\n"},
            description="翻译")
        self.ctx.modules.publish(
            "search", "1.0.0",
            {"engine.py": b"def run(q):\n    return []\n"},
            description="检索")

    def issue(self, *, items=None, hid: str = _HID):
        return self.client.post("/v1/agents/issue", json={
            "identityHash": hid,
            "selection": {"items": items or [{"moduleId": "summarize", "version": "1.0.0"}]},
        })

    def close(self) -> None:
        self.client.close()
        self.tmp.cleanup()


class env_ctx:
    """with 语法糖：退出时清理临时目录与连接。"""

    def __init__(self) -> None:
        self.e: Env | None = None

    def __enter__(self) -> Env:
        self.e = Env()
        return self.e

    def __exit__(self, *exc) -> None:
        if self.e is not None:
            self.e.close()


# ---------------------------------------------------------------------------
# 1. 健康与自检
# ---------------------------------------------------------------------------


def test_healthz_reports_healthy():
    _skip()
    with env_ctx() as e:
        r = e.client.get("/healthz")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ok", body
        assert body["problems"] == []


def test_app_requires_explicit_context():
    """不许"什么都不给也能起" —— 否则有人会以为它工作了。"""
    app_mod = load_agent_service_app()
    try:
        app_mod.create_app()
    except RuntimeError as exc:
        assert "dev_store" in str(exc)
    else:
        raise AssertionError("create_app 无参调用竟然成功了")


# ---------------------------------------------------------------------------
# 2. 申领主链路
# ---------------------------------------------------------------------------


def test_issue_end_to_end_lands_in_localstore():
    _skip()
    with env_ctx() as e:
        r = e.issue()
        assert r.status_code == 200, r.text
        out = r.json()

        did = out["did"]
        assert did.startswith("did:tpaa:primary:"), did
        assert out["cmi"] and len(out["cmi"]) == 64, out["cmi"]
        assert out["buildDigest"], "缺少 buildDigest"
        assert out["layers"], "缺少逐层哈希链"
        assert out["keptExisting"] is False

        # --- PHC 里该有的都写上了 ---
        phc = out["phc"]
        assert phc["ASO"]["TPM"]["CDID"] == did, "TP 没把 DID 写进 TPM"
        assert phc["ASO"]["TPM"]["ECID"], "ECID 没封"
        assert phc["ASO"]["APM"]["CMI"] == out["cmi"], "CMI 没写进 APM"
        assert phc["APA"]["APid"], "AP 公钥没落进 APA"

        # --- 落到 localstore 的东西 ---
        d = e.ctx.layout.agent_dir(did)
        assert d.is_dir(), "没有实例目录"
        for name in ("meta.json", "selection.json", "cmi.json", "phc.json",
                     "versions.json"):
            assert (d / name).is_file(), f"缺少 {name}"
        assert (d / "build" / "1").is_dir(), "缺少 build/1"
        assert (d / "build" / "1" / "agent.yaml").is_file()

        meta_text = (d / "meta.json").read_text(encoding="utf-8")
        assert _HID.removeprefix("0x") not in meta_text, \
            "meta.json 里出现了 H(ID) 明文 —— 身份不应落在实例目录"

        cmi = json.loads((d / "cmi.json").read_text(encoding="utf-8"))
        assert cmi["cmi"] == out["cmi"]


def test_issue_is_verifiable_by_third_party_public_material():
    """凭证要能被第三方用公开材料验过 —— 这是"平台签出的东西可信"的最低标准。"""
    _skip()
    with env_ctx() as e:
        out = e.issue().json()
        v = e.ctx.capability.verify_phc(
            out["phc"], identity_hash=int(_HID, 16), tau=1, crf=1)
        assert v.ok, v.errors


def test_duplicate_issue_returns_same_instance():
    """同一人、同一份选择，不重复生成（否则台账开始漂）。"""
    _skip()
    with env_ctx() as e:
        a = e.issue().json()
        b = e.issue().json()
        assert a["did"] == b["did"]
        assert b["keptExisting"] is True
        assert len(list(e.ctx.agents.iter_all())) == 1


def test_same_user_different_selection_gets_second_agent():
    """一人多体是合法需求，不能被"查重"顺手拒掉。"""
    _skip()
    with env_ctx() as e:
        a = e.issue(items=[{"moduleId": "summarize", "version": "1.0.0"}]).json()
        b = e.issue(items=[
            {"moduleId": "summarize", "version": "1.0.0"},
            {"moduleId": "translate", "version": "1.0.0"},
        ]).json()
        assert a["did"] != b["did"]
        assert a["cmi"] != b["cmi"], "选择不同，CMI 必须不同"


def test_issue_rejects_revoked_module():
    _skip()
    with env_ctx() as e:
        e.ctx.modules.revoke("search", "1.0.0")
        r = e.issue(items=[{"moduleId": "search", "version": "1.0.0"}])
        assert r.status_code == 400, r.text
        assert "下架" in r.json()["message"]


def test_issue_rejects_unknown_module():
    _skip()
    with env_ctx() as e:
        r = e.issue(items=[{"moduleId": "nope", "version": "9.9.9"}])
        assert r.status_code == 400
        assert "不存在" in r.json()["message"]


def test_issue_rejects_bad_identity_hash_format():
    _skip()
    with env_ctx() as e:
        r = e.issue(hid="not-a-hash")
        assert r.status_code == 422, r.text      # pydantic 校验层拦下


# ---------------------------------------------------------------------------
# 3. 派生：闸门必须先于一切
# ---------------------------------------------------------------------------


def _derive_body(e: Env, parent: str, *, token=None, items=None):
    return {
        "parentDid": parent,
        "selection": {"items": items or [{"moduleId": "search", "version": "1.0.0"}]},
        "ttlHours": 24,
        "confirmToken": token,
    }


def test_derive_without_confirmation_is_rejected_before_any_side_effect():
    """没有令牌 ⇒ 403，且**什么都没发生**：没新实例、没要 DID、没写索引。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        before = len(list(e.ctx.agents.iter_all()))

        r = e.client.post("/v1/subagents/derive", json=_derive_body(e, parent))
        assert r.status_code == 403, r.text
        assert r.json()["code"] == 1401
        assert "确认" in r.json()["message"]
        assert len(list(e.ctx.agents.iter_all())) == before, "闸门没挡在副作用之前"


def test_derive_prepare_does_not_touch_keys_or_store():
    """prepare 只出"确认任务"，不产生实例、不发令牌。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        before = len(list(e.ctx.agents.iter_all()))
        r = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent,
            "selection": {"items": [{"moduleId": "search", "version": "1.0.0"}]},
            "ttlHours": 24,
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["selectionDigest"] and len(body["selectionDigest"]) == 64
        assert "确认" in body["summary"]
        assert len(list(e.ctx.agents.iter_all())) == before


def test_derive_happy_path_after_confirmation():
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        items = [{"moduleId": "search", "version": "1.0.0"}]

        prep = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
        }).json()

        conf = e.client.post("/v1/subagents/confirm", json={
            "ticketId": prep["ticketId"], "parentDid": parent,
            "selection": {"items": items}, "ttlHours": 24,
            "selectionDigest": prep["selectionDigest"],
        })
        assert conf.status_code == 200, conf.text
        token = conf.json()["token"]

        r = e.client.post("/v1/subagents/derive",
                          json=_derive_body(e, parent, token=token, items=items))
        assert r.status_code == 200, r.text
        child = r.json()

        assert child["did"] != parent
        assert child["did"].startswith("did:tpaa:sub:")
        assert child["parentDid"] == parent
        assert child["expiresAt"] > prep["createdAt"]

        # 子体是**独立实例**：有自己的 PHC、自己的 build、自己的 CMI
        cdir = e.ctx.layout.agent_dir(child["did"])
        assert (cdir / "phc.json").is_file()
        assert (cdir / "build" / "1").is_file
        assert child["phc"]["parentDid"] == parent, "子体 PHC 未封父 DID"
        assert child["phc"]["ASO"]["TPM"]["CDID"] == child["did"]

        meta = e.ctx.agents.load_meta(child["did"])
        assert meta.agent_type.value == "sub"
        assert meta.owner_did == parent, "子体应归自然人主 DID 管，而不是挂在父体名下"


def test_derive_token_is_single_use():
    """同一张票不能派生第二个子体。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        items = [{"moduleId": "search", "version": "1.0.0"}]
        prep = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
        }).json()
        token = e.client.post("/v1/subagents/confirm", json={
            "ticketId": prep["ticketId"], "parentDid": parent,
            "selection": {"items": items}, "ttlHours": 24,
            "selectionDigest": prep["selectionDigest"],
        }).json()["token"]

        ok = e.client.post("/v1/subagents/derive",
                           json=_derive_body(e, parent, token=token, items=items))
        assert ok.status_code == 200, ok.text

        again = e.client.post("/v1/subagents/derive",
                              json=_derive_body(e, parent, token=token, items=items))
        assert again.status_code == 403, again.text
        assert again.json()["code"] == 1401
        assert "使用" in again.json()["message"]


def test_derive_token_bound_to_selection():
    """确认后偷换模块，同一张令牌必须失效。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        items = [{"moduleId": "search", "version": "1.0.0"}]
        prep = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
        }).json()
        token = e.client.post("/v1/subagents/confirm", json={
            "ticketId": prep["ticketId"], "parentDid": parent,
            "selection": {"items": items}, "ttlHours": 24,
            "selectionDigest": prep["selectionDigest"],
        }).json()["token"]

        # 确认的是 search，执行时换成 translate
        r = e.client.post("/v1/subagents/derive", json=_derive_body(
            e, parent, token=token,
            items=[{"moduleId": "translate", "version": "1.0.0"}]))
        assert r.status_code == 403, r.text
        assert "被改动" in r.json()["message"] or "不一致" in r.json()["message"]


def test_confirm_rejects_digest_mismatch():
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        items = [{"moduleId": "search", "version": "1.0.0"}]
        prep = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
        }).json()
        r = e.client.post("/v1/subagents/confirm", json={
            "ticketId": prep["ticketId"], "parentDid": parent,
            "selection": {"items": items}, "ttlHours": 24,
            "selectionDigest": "0" * 64,
        })
        assert r.status_code == 403, r.text


def test_sub_cannot_derive_further():
    """子体不能再派生 —— 否则追溯链成树，"根"不唯一。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        items = [{"moduleId": "search", "version": "1.0.0"}]
        prep = e.client.post("/v1/subagents/prepare", json={
            "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
        }).json()
        token = e.client.post("/v1/subagents/confirm", json={
            "ticketId": prep["ticketId"], "parentDid": parent,
            "selection": {"items": items}, "ttlHours": 24,
            "selectionDigest": prep["selectionDigest"],
        }).json()["token"]
        child = e.client.post("/v1/subagents/derive",
                              json=_derive_body(e, parent, token=token,
                                                items=items)).json()["did"]

        r = e.client.post("/v1/subagents/prepare", json={
            "parentDid": child,
            "selection": {"items": [{"moduleId": "search", "version": "1.0.0"}]},
            "ttlHours": 12,
        })
        assert r.status_code == 400, r.text
        assert "只有主智能体" in r.json()["message"]


# ---------------------------------------------------------------------------
# 4. 找回
# ---------------------------------------------------------------------------


def _issue_child(e: Env, parent: str) -> str:
    items = [{"moduleId": "search", "version": "1.0.0"}]
    prep = e.client.post("/v1/subagents/prepare", json={
        "parentDid": parent, "selection": {"items": items}, "ttlHours": 24,
    }).json()
    token = e.client.post("/v1/subagents/confirm", json={
        "ticketId": prep["ticketId"], "parentDid": parent,
        "selection": {"items": items}, "ttlHours": 24,
        "selectionDigest": prep["selectionDigest"],
    }).json()["token"]
    return e.client.post("/v1/subagents/derive",
                         json=_derive_body(e, parent, token=token,
                                           items=items)).json()["did"]


def test_locate_lists_all_instances_under_one_identity():
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        child = _issue_child(e, parent)

        r = e.client.get("/v1/agents/locate", params={"identityHash": _HID})
        assert r.status_code == 200, r.text
        dids = {i["did"] for i in r.json()["items"]}
        assert dids == {parent, child}, dids


def test_locate_does_not_change_state():
    """"看一眼"不该顺手冻东西。"""
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        child = _issue_child(e, parent)
        e.clock.advance(hours=48)                 # 子体已过期

        before = e.ctx.agents.load_meta(child).state
        e.client.get("/v1/agents/locate", params={"identityHash": _HID})
        assert e.ctx.agents.load_meta(child).state == before, "locate 改了状态"


def test_recover_rebuilds_main_agent():
    _skip()
    with env_ctx() as e:
        out = e.issue().json()
        did = out["did"]

        # 模拟"本地 build 丢了"—— 这正是找回要解决的场景
        import shutil
        shutil.rmtree(e.ctx.layout.agent_dir(did) / "build")

        r = e.client.post("/v1/agents/recover",
                          json={"identityHash": _HID, "did": did})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["rebuilt"] is True
        assert body["cmi"] == out["cmi"], "重算出的 CMI 必须与当初一致"
        assert body["buildDigest"] == out["buildDigest"], "确定性重建应得到同一份 build"
        assert (e.ctx.layout.agent_dir(did) / "build" / "1" / "agent.yaml").is_file()


def test_recover_rejects_someone_elses_did():
    """拿别人的 DID 来重建 —— 必须拒。"""
    _skip()
    with env_ctx() as e:
        a = e.issue(hid="0x" + "22" * 32).json()["did"]
        r = e.client.post("/v1/agents/recover",
                          json={"identityHash": _HID, "did": a})
        assert r.status_code == 400, r.text
        assert "不在该身份名下" in r.json()["message"]


def test_recover_detects_module_tampering_and_freezes():
    """模块内容被换 ⇒ CMI 不一致 ⇒ 冻结 + 409，且**不自动修复**。"""
    _skip()
    with env_ctx() as e:
        did = e.issue().json()["did"]

        # 绕过仓库校验直接改盘上的模块文件（模拟越权改动 / 磁盘损坏）
        target = e.ctx.layout.module_dir("summarize", "1.0.0") / "engine.py"
        import os
        import stat
        os.chmod(target, stat.S_IWRITE)
        target.write_bytes(b"def run(text):\n    return 'pwned'\n")

        r = e.client.post("/v1/agents/recover",
                          json={"identityHash": _HID, "did": did})
        assert r.status_code == 409, r.text
        assert "冻结" in r.json()["message"]

        meta = e.ctx.agents.load_meta(did)
        assert meta.state.value == "frozen", "CMI 不一致后必须冻结"
        assert (e.ctx.layout.agent_dir(did) / "meta.json").is_file(), \
            "冻结不等于删除 —— 实例要留着取证"


def test_frozen_agent_cannot_be_delivered():
    _skip()
    with env_ctx() as e:
        did = e.issue().json()["did"]
        e.ctx.agents.freeze(did, "人工冻结", at=e.clock.now())
        r = e.client.post("/v1/agents/recover",
                          json={"identityHash": _HID, "did": did})
        assert r.status_code == 409, r.text
        assert "冻结" in r.json()["message"]


def test_sweep_freezes_expired_sub_but_keeps_parent():
    _skip()
    with env_ctx() as e:
        parent = e.issue().json()["did"]
        child = _issue_child(e, parent)
        e.clock.advance(hours=25)

        r = e.client.post("/v1/agents/sweep")
        assert r.status_code == 200, r.text
        assert child in r.json()["frozen"]
        assert e.ctx.agents.load_meta(child).state.value == "frozen"
        assert e.ctx.agents.load_meta(parent).state.value == "active"
        assert (e.ctx.layout.agent_dir(child) / "meta.json").is_file(), "清扫不得删文件"


# ---------------------------------------------------------------------------
# 5. 红线：localstore 里不许出现的东西
# ---------------------------------------------------------------------------


def test_no_plaintext_identity_or_cid_in_store():
    _skip()
    with env_ctx() as e:
        did = e.issue().json()["did"]
        _issue_child(e, did)

        hid = _HID.removeprefix("0x")
        for p in Path(e.tmp.name).rglob("*"):
            if not p.is_file() or p.suffix in {".db"}:
                continue
            blob = p.read_bytes()
            if p.name.startswith(("engine", "manifest")) or "modules" in p.parts:
                continue                        # 模块代码本来就是公开的
            assert hid.encode() not in blob, f"{p} 出现 H(ID) 明文"
            assert b"tpaa://" not in blob, f"{p} 出现内容定位串（应只存 ECID）"


def test_index_is_not_plaintext_mapping():
    """身份索引是全库唯一含身份映射的文件，必须是密文。"""
    _skip()
    with env_ctx() as e:
        did = e.issue().json()["did"]
        idx = e.ctx.layout.identity_index
        blob = idx.read_bytes()
        assert _HID.removeprefix("0x").encode() not in blob
        assert did.encode() not in blob
        # 但用正确密钥解得回来
        assert did in e.ctx.identity_index.lookup(
            _HID.removeprefix("0x"), opener=e.ctx.opener())
