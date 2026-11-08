"""A 轮真实进程 smoke：执行器独立进程 + B1 challenge/sign/login 认证链路。

覆盖范围（故意收窄，不夸大）：
    ✓ 执行器是真的另一个 OS 进程，经 TCP loopback 通信
    ✓ 域服务发 challenge → 执行器用用户密钥签名 → 换到域令牌 → 用令牌调业务端点
    ✓ 门户不持有任何 TP/AP 的 AUTH 种子，签名动作只发生在执行器进程里
    ✗ 不覆盖 TP 侧独立部署 —— phc-service 的 `_from_env()` 明确 raise，
      本轮用同进程 TP domain 装配（见 RUNNING.md 的"当前边界"）
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
pytest.importorskip("uvicorn")

import crypto.sdk  # noqa: E402

v1 = crypto.sdk.v1
TOKEN = "smoke-executor-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ExecutorProcess:
    """真进程执行器：uvicorn 子进程 + TCP loopback。"""

    def __init__(self, state_root: Path) -> None:
        self.state_root = state_root
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = dict(os.environ,
                   TPAA_EXECUTOR_STATE_ROOT=str(state_root),
                   TPAA_EXECUTOR_TOKEN=TOKEN,
                   TPAA_EXECUTOR_BIND="127.0.0.1",
                   PYTHONPATH=str(ROOT))
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn",
             "services.user_side.executor_service.app:app",
             "--host", "127.0.0.1", "--port", str(self.port),
             "--workers", "1", "--log-level", "warning"],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self._await_ready()

    def _await_ready(self, timeout: float = 60.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = (self.proc.stdout.read() or b"").decode("utf-8", "replace")
                raise RuntimeError(f"执行器进程退出（{self.proc.returncode}）：\n{out}")
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=2) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.3)
        raise RuntimeError("执行器进程未在时限内就绪")

    def call(self, path: str, body: dict | None = None, *, method: str = "POST") -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))

    @property
    def pid(self) -> int:
        return self.proc.pid

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


@pytest.fixture(scope="module")
def executor(tmp_path_factory):
    proc = ExecutorProcess(tmp_path_factory.mktemp("smoke-executor") / "state")
    try:
        yield proc
    finally:
        proc.close()


@pytest.fixture(scope="module")
def domain(executor):
    """一个真实的域服务（identity-service），用它的 challenge/login 做 B1。"""
    from fastapi.testclient import TestClient

    from services.shared.v1_auth import AuthIssuer
    from services.shared.v1_http import FixedClock
    import services.tp_side.identity_service.app as ident
    import services.tp_side.identity_service.infra.wiring as wiring

    clock = FixedClock("2026-10-14T10:00:00")
    tp_hsm = v1.make_demo_hsm(domain="TP")
    tmp = tmp_path = Path(executor.state_root).parent / "domain"
    tmp.mkdir(parents=True, exist_ok=True)
    auth = AuthIssuer(issuer_hsm=v1.make_demo_hsm(domain="AUTH"), aud="tpaa:tp", clock=clock)
    ctx = wiring.build_context(tp_hsm=tp_hsm, db_path=str(tmp / "identity.json"),
                               clock=clock, test_adapter=True)
    return TestClient(ident.create_app(ctx=ctx, auth=auth))


def test_executor_runs_in_a_separate_process(executor):
    """进程隔离是真的：PID 不是本测试进程。"""
    assert executor.pid != os.getpid()
    assert executor.proc.poll() is None, "执行器进程应当还活着"
    health = executor.call("/healthz", method="GET")
    assert health["status"] == "ok"
    assert health["profile"] == "test-adapter", "必须如实标注是测试 adapter"


def test_b1_challenge_sign_login_over_real_socket(executor, domain):
    """★ B1 全链路：域发 challenge → 执行器进程签名 → 域换令牌 → 令牌调业务端点。

    关键点：签名发生在另一个进程里。本测试进程（扮演门户）从头到尾
    没有用户私钥，只转发 challenge 和签名结果。
    """
    challenge = domain.post("/v1/auth/challenge").json()
    assert challenge["aud"] == "tpaa:tp"

    # 签名由执行器进程做 —— 门户只是转发
    signed = executor.call("/v1/executor/login-body", {"challenge": challenge})
    assert signed["challenge"] == challenge["challenge"]

    # 执行器的公钥与它自称的 owner 对得上
    pub = executor.call("/v1/executor/public-key", method="GET")
    assert signed["signPk"] == pub["signPk"]
    assert v1.owner_of(v1.pk_from_hex(signed["signPk"])) == pub["owner"]

    # 换令牌
    login = domain.post("/v1/auth/login", json=signed)
    assert login.status_code == 200, login.text
    token = login.json()["token"]

    # 用令牌调真实业务端点
    slot = domain.post("/v1/slots", json={"userSignPk": signed["signPk"]},
                       headers={"Authorization": f"Bearer {token}"})
    assert slot.status_code == 200, slot.text
    assert slot.json()["nonce"]


def test_challenge_is_single_use_over_real_socket(executor, domain):
    """同一 challenge 第二次登录 401 —— 一次性消费在真链路上成立。"""
    challenge = domain.post("/v1/auth/challenge").json()
    signed = executor.call("/v1/executor/login-body", {"challenge": challenge})
    assert domain.post("/v1/auth/login", json=signed).status_code == 200
    assert domain.post("/v1/auth/login", json=signed).status_code == 401


def test_business_endpoint_rejects_missing_token(domain):
    """没有令牌直接调业务端点 —— 401。"""
    assert domain.post("/v1/slots", json={"userSignPk": "00" * 33}).status_code == 401


def test_executor_rejects_calls_without_its_own_token(executor):
    """执行器自己的 token 也是必须的：loopback 不等于免认证。"""
    req = urllib.request.Request(executor.base + "/v1/executor/public-key", method="GET")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(req, timeout=10)
    assert caught.value.code == 401


def test_user_private_key_never_crosses_the_socket(executor, domain):
    """执行器的响应里不含私钥材料 —— 只有公钥和签名。"""
    challenge = domain.post("/v1/auth/challenge").json()
    signed = executor.call("/v1/executor/login-body", {"challenge": challenge})
    pub = executor.call("/v1/executor/public-key", method="GET")
    blob = json.dumps({"signed": signed, "pub": pub})
    for leak in ("schnorr_sk", "chameleon_sk", "root", "seed", "privateKey"):
        assert leak not in blob, f"执行器响应里出现了 {leak}"
    # keys.json 明文密钥留在执行器进程的状态目录里，没有经过网络
    keys_file = Path(executor.state_root) / "keys.json"
    assert keys_file.exists(), "测试 adapter 的 keys.json 应当在执行器侧"
    assert keys_file.read_text(encoding="utf-8") not in blob
