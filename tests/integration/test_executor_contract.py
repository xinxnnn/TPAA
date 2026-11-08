"""执行器 HTTP 契约：同一套用例跑两种 transport。

两种 transport：
    testclient  —— ASGI 内存调用（整合测试用的那条）
    socket      —— 真的起一个独立进程，走 TCP loopback

★ 为什么要两种都跑：内存 transport 跑过不代表真部署形态跑得过（限长、
  JSON 解析、认证头、进程边界都只在真 socket 上才成立）；只跑真进程又太慢，
  日常回归需要快的那条。契约必须是同一份，否则两条路会悄悄长歪。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from services.user_side.executor_service.app import (  # noqa: E402
    MAX_BODY_BYTES, ExecutorContext, create_app,
)
from user_credential_handler import UserCredentialHandler  # noqa: E402

TOKEN = "contract-executor-token"


class _TestClientTransport:
    """ASGI 内存 transport。"""

    name = "testclient"

    def __init__(self, tmp_path):
        from fastapi.testclient import TestClient
        self.handler = UserCredentialHandler(tmp_path / "state")
        self.client = TestClient(create_app(
            ctx=ExecutorContext(handler=self.handler, token=TOKEN)))

    @property
    def owner(self) -> str:
        return self.handler.owner

    def post(self, path: str, body, *, token: str = TOKEN, raw: bytes | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if raw is not None:
            headers["Content-Type"] = "application/json"
            r = self.client.post(path, content=raw, headers=headers)
        else:
            r = self.client.post(path, json=body, headers=headers)
        return r.status_code, _json_or_text(r.text)

    def get(self, path: str, *, token: str = TOKEN):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self.client.get(path, headers=headers)
        return r.status_code, _json_or_text(r.text)

    def close(self):
        pass


class _SocketTransport:
    """真进程 + TCP loopback transport。"""

    name = "socket"

    def __init__(self, tmp_path):
        self.root = tmp_path / "state"
        self.handler = UserCredentialHandler(self.root)
        self.port = _free_port()
        env = dict(os.environ,
                   TPAA_EXECUTOR_STATE_ROOT=str(self.root),
                   TPAA_EXECUTOR_TOKEN=TOKEN,
                   TPAA_EXECUTOR_BIND="127.0.0.1",
                   PYTHONPATH=str(ROOT))
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn",
             "services.user_side.executor_service.app:app",
             "--host", "127.0.0.1", "--port", str(self.port),
             "--workers", "1", "--log-level", "warning"],
            cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.base = f"http://127.0.0.1:{self.port}"
        self._await_ready()

    def _await_ready(self, timeout: float = 45.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = (self.proc.stdout.read() or b"").decode("utf-8", "replace")
                raise RuntimeError(f"执行器进程退出了（{self.proc.returncode}）：\n{out}")
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.3)
        raise RuntimeError("执行器进程未在时限内就绪")

    @property
    def owner(self) -> str:
        return self.handler.owner

    def _send(self, method: str, path: str, data: bytes | None, token: str | None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, _json_or_text(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # 413 时服务端可能在 body 读完之前就断连，读响应体会抛 IncompleteRead。
            # 状态码才是契约；响应体读不到不算用例失败。
            try:
                text = exc.read().decode("utf-8", "replace")
            except Exception:                                    # noqa: BLE001
                text = ""
            return exc.code, _json_or_text(text)

    def post(self, path: str, body, *, token: str = TOKEN, raw: bytes | None = None):
        data = raw if raw is not None else json.dumps(body).encode("utf-8")
        return self._send("POST", path, data, token)

    def get(self, path: str, *, token: str = TOKEN):
        return self._send("GET", path, None, token)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


def _json_or_text(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return {"raw": text}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def _transports(tmp_path_factory):
    """两种 transport 各装配一次。

    ★ 真进程只起一次：每个用例起一个 uvicorn 要几十秒。
      用例之间靠各自独立的 label 隔离（见 tx 夹具），不靠重启进程。
    """
    made = {}
    try:
        made["testclient"] = _TestClientTransport(tmp_path_factory.mktemp("tc"))
        if not os.environ.get("TPAA_SKIP_SOCKET_TESTS"):
            try:
                import uvicorn  # noqa: F401
                made["socket"] = _SocketTransport(tmp_path_factory.mktemp("sock"))
            except ImportError:
                pass
        yield made
    finally:
        for t in made.values():
            t.close()


@pytest.fixture(params=["testclient", "socket"])
def tx(request, _transports):
    """同一套契约在两种 transport 上各跑一遍，每个用例拿到独立的 label / appId。"""
    transport = _transports.get(request.param)
    if transport is None:
        pytest.skip(f"{request.param} transport 不可用")
    # 每个用例一组独立标识：共享进程但不共享状态
    tag = request.node.name.replace("[", "-").replace("]", "").replace("_", "-")
    transport.label = f"lb-{tag}"[:60]
    transport.app_id = f"app-{tag}"[:60]
    return transport


def _make_cr(tx, label: str | None = None):
    """走 G1 建一个执行标签。

    TP / AP 的密钥与槽位用本地 demo HSM 生成 —— 契约测试只关心执行器的 HTTP 表面，
    这份 CR 不提交给任何服务，但结构必须是真的（执行器会真的做密码学运算）。
    """
    import crypto.sdk
    v1 = crypto.sdk.v1
    tp, ap = v1.make_demo_hsm(domain="TP"), v1.make_demo_hsm(domain="AP")
    owner = tx.owner
    tp_nonce, tp_pub = tp.allocate_slot(owner)
    ap_nonce, ap_pub = ap.allocate_slot(owner)
    return tx.post("/v1/executor/build-cr", {
        "label": label or tx.label, "owner": owner,
        "pii": {"ID": "110101199003071234", "name": "张三"},
        "bi": {"iris": "iris-template-demo"},
        "tp_keys": {"signPk": v1.pk_hex(tp.pubkey()), "encPub": format(tp.enc_pub(), "x")},
        "ap_keys": {"signPk": v1.pk_hex(ap.pubkey()), "encPub": format(ap.enc_pub(), "x")},
        "tp_slot": {"nonce": tp_nonce, "pub": format(tp_pub, "x")},
        "ap_slot": {"nonce": ap_nonce, "pub": format(ap_pub, "x")},
        "expires": "2026-10-14T11:00:00",
    })


def _bind(tx, app_id: str | None = None, label: str | None = None, *, fresh: bool = True):
    label = label or tx.label
    app_id = app_id or tx.app_id
    if fresh:
        status, body = _make_cr(tx, label)
        assert status == 200, f"build-cr 失败：{status} {body}"
    return tx.post("/v1/executor/set-application",
                   {"label": label, "owner": tx.owner, "appId": app_id,
                    "requestId": f"{app_id}:set-application"})


# ---------------------------------------------------------------------------
# 认证
# ---------------------------------------------------------------------------


def test_requires_token(tx):
    status, _ = tx.post("/v1/executor/events",
                        {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id},
                        token=None)
    assert status == 401
    assert tx.get("/v1/executor/public-key", token=None)[0] == 401


def test_wrong_token_is_401(tx):
    status, _ = tx.get("/v1/executor/public-key", token="not-the-token")
    assert status == 401


# ---------------------------------------------------------------------------
# owner / 应用绑定
# ---------------------------------------------------------------------------


def test_other_owner_is_403(tx):
    status, _ = tx.post("/v1/executor/events",
                        {"label": tx.label, "owner": "owner-someone-else",
                         "applicationId": tx.app_id})
    assert status == 403


def test_operation_without_application_id_is_409(tx):
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/accept-g4",
                           {"label": tx.label, "owner": tx.owner,
                            "requestId": "r-no-app"})
    assert status == 409, body


def test_unbound_label_is_409(tx):
    status, body = tx.post("/v1/executor/accept-g4",
                           {"label": "never-bound", "owner": tx.owner,
                            "applicationId": tx.app_id, "requestId": "r-unbound"})
    assert status == 409, body


def test_mismatched_application_is_403(tx):
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/accept-g4",
                           {"label": tx.label, "owner": tx.owner,
                            "applicationId": "app-other", "requestId": "r-mismatch"})
    assert status == 403, body


def test_rebinding_label_to_another_application_is_403(tx):
    assert _bind(tx)[0] == 200
    status, _ = _bind(tx, app_id="app-other", fresh=False)
    assert status == 403


def test_binding_is_readable_and_authoritative(tx):
    assert tx.get(f"/v1/executor/{tx.label}/application")[1]["applicationId"] is None
    assert _bind(tx)[0] == 200
    assert tx.get(f"/v1/executor/{tx.label}/application")[1]["applicationId"] == tx.app_id


# ---------------------------------------------------------------------------
# 字段表 / 限长
# ---------------------------------------------------------------------------


def test_unknown_operation_is_404(tx):
    status, _ = tx.post("/v1/executor/no-such-operation",
                        {"label": tx.label, "owner": tx.owner})
    assert status == 404


def test_unknown_field_is_400(tx):
    """多一个字段就是 400 —— 以前是静默丢弃。"""
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/build-ar",
                           {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
                            "requestId": "r-extra", "expires": "2026-10-14T11:00:00",
                            "expiry": "typo-field"})
    assert status == 400, body
    assert "expiry" in str(body)


def test_missing_required_field_is_400(tx):
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/build-ar",
                           {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
                            "requestId": "r-missing"})
    assert status == 400, body
    assert "expires" in str(body)


def test_mutating_operation_requires_request_id(tx):
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/build-ar",
                           {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
                            "expires": "2026-10-14T11:00:00"})
    assert status == 400, body
    assert "requestId" in str(body)


def test_missing_label_is_400(tx):
    status, _ = tx.post("/v1/executor/events", {"owner": tx.owner, "applicationId": tx.app_id})
    assert status == 400


def test_oversized_body_is_413(tx):
    assert _bind(tx)[0] == 200
    payload = json.dumps({
        "label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
        "requestId": "r-big", "cmm": {"padding": "x" * (MAX_BODY_BYTES + 4096)},
    }).encode("utf-8")
    assert len(payload) > MAX_BODY_BYTES
    status, _ = tx.post("/v1/executor/open-cmm", None, raw=payload)
    assert status == 413


def test_malformed_json_is_400(tx):
    status, _ = tx.post("/v1/executor/events", None, raw=b"{not json")
    assert status == 400


def test_non_object_body_is_400(tx):
    status, _ = tx.post("/v1/executor/events", None, raw=b"[1,2,3]")
    assert status == 400


# ---------------------------------------------------------------------------
# 幂等
# ---------------------------------------------------------------------------


def test_replayed_request_returns_first_result(tx):
    """同一 requestId + 同一内容：返回首次结果，handler 不再被调用。

    怎么证明"没再调用"：accept-rr 的第二次执行一定会因阶段不符抛 409
    （首次已把 stage 推到 cred）。拿到与首次一样的响应，说明它在幂等层就返回了。
    """
    assert _bind(tx)[0] == 200
    body = {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
            "requestId": "r-replay", "rr": {"not": "a real rr"}}
    first = tx.post("/v1/executor/accept-rr", body)
    replay = tx.post("/v1/executor/accept-rr", dict(body))
    assert replay == first, "重放应返回首次结果，而不是再执行一次"


def test_same_request_id_with_different_body_is_409(tx):
    """撞号：同一 requestId 配不同内容是客户端错误，不能静默返回旧结果。"""
    status, body = _make_cr(tx)
    assert status == 200, body
    rid = "r-collide"
    first = tx.post("/v1/executor/set-application",
                    {"label": tx.label, "owner": tx.owner, "appId": tx.app_id,
                     "requestId": rid})
    assert first[0] == 200, first
    status, payload = tx.post("/v1/executor/set-application",
                              {"label": tx.label, "owner": tx.owner,
                               "appId": "app-different", "requestId": rid})
    assert status == 409, payload
    # 绑定没有被第二次请求改动
    assert tx.get(f"/v1/executor/{tx.label}/application")[1]["applicationId"] == tx.app_id


def test_different_request_id_is_executed(tx):
    """换号就是新请求：绑定替换这时才真的被 handler 拒掉。"""
    assert _bind(tx)[0] == 200
    status, _ = tx.post("/v1/executor/set-application",
                        {"label": tx.label, "owner": tx.owner, "appId": "app-different",
                         "requestId": "r-another-number"})
    assert status == 403


def test_wrong_order_operation_is_409(tx):
    """没走到那一步就调下一步 —— handler 的阶段检查映射成 409。"""
    assert _bind(tx)[0] == 200
    status, body = tx.post("/v1/executor/accept-g4",
                           {"label": tx.label, "owner": tx.owner, "applicationId": tx.app_id,
                            "requestId": "r-order"})
    assert status == 409, body


# ---------------------------------------------------------------------------
# 敏感材料不出现在响应里
# ---------------------------------------------------------------------------


def test_public_key_response_has_no_private_material(tx):
    status, body = tx.get("/v1/executor/public-key")
    assert status == 200
    text = json.dumps(body)
    for leak in ("schnorr_sk", "chameleon_sk", "seed", "privateKey", "sk"):
        assert leak not in text, f"响应里出现了 {leak}"
    assert body["profile"] == "test-adapter"


def test_pending_request_without_binding_is_allowed(tx):
    """pending-request 不要求 applicationId（创建申请时绑定还没建立）。"""
    status, _ = tx.post("/v1/executor/pending-request",
                        {"label": "fresh-label", "owner": tx.owner})
    assert status in (200, 409), "应当是正常响应或阶段冲突，而不是字段/绑定错误"
