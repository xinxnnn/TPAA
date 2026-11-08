"""认证契约：单 worker 启动守卫 + challenge 一次性消费。

为什么这两件事绑在一起测：`AuthIssuer` 的 challenge 是进程内字典，
一次性消费只在"单进程"前提下成立。守卫没了，并发测试过了也不算安全。
"""

from __future__ import annotations

import sys
import threading

import pytest

import crypto.sdk
from services.shared.v1_auth import AuthIssuer, Unauthenticated
from services.shared.v1_http import FixedClock, assert_single_worker

v1 = crypto.sdk.v1


@pytest.fixture()
def auth():
    """一个单账号的 AuthIssuer 和它认得的那把 staff HSM。"""
    clock = FixedClock()
    staff = v1.make_demo_hsm(domain="STAFF")
    pk_hex = v1.pk_hex(staff.pubkey())
    issuer = AuthIssuer(issuer_hsm=v1.make_demo_hsm(domain="AUTH"), aud="tpaa:tp", clock=clock,
                        staff={pk_hex: {"id": "u-1", "role": "reviewer"}})
    return issuer, staff, pk_hex


class TestSingleWorkerGuard:
    def test_accepts_default_single_process_start(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["uvicorn", "svc.app:app", "--workers", "1"])
        for var in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
            monkeypatch.delenv(var, raising=False)
        assert_single_worker("svc") is None

    @pytest.mark.parametrize("argv", [
        ["uvicorn", "svc.app:app", "--workers", "4"],
        ["uvicorn", "svc.app:app", "--workers=2"],
        ["uvicorn", "svc.app:app", "-w", "8"],
    ])
    def test_refuses_multi_worker_argv(self, monkeypatch, argv):
        monkeypatch.setattr(sys, "argv", argv)
        for var in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(RuntimeError, match="单 worker"):
            assert_single_worker("svc")

    @pytest.mark.parametrize("var", ["WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"])
    def test_refuses_multi_worker_env(self, monkeypatch, var):
        monkeypatch.setattr(sys, "argv", ["uvicorn", "svc.app:app"])
        for other in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
            monkeypatch.delenv(other, raising=False)
        monkeypatch.setenv(var, "3")
        with pytest.raises(RuntimeError, match="单 worker"):
            assert_single_worker("svc")

    def test_refuses_spawned_worker_child(self, monkeypatch):
        import multiprocessing
        monkeypatch.setattr(sys, "argv", ["uvicorn", "svc.app:app"])
        monkeypatch.setattr(multiprocessing, "parent_process", lambda: object())
        with pytest.raises(RuntimeError, match="worker 子进程"):
            assert_single_worker("svc")


class TestChallengeOneShot:
    def _login_args(self, issuer, staff, pk_hex):
        c = issuer.challenge()["challenge"]
        sig = v1.auth.sign_login(staff, challenge=c, aud=issuer.aud)
        return {"challenge": c, "sign_pk": pk_hex, "sig": sig}

    def test_replay_of_same_challenge_is_rejected(self, auth):
        issuer, staff, pk_hex = auth
        args = self._login_args(issuer, staff, pk_hex)
        assert issuer.login(**args)["token"]
        with pytest.raises(Unauthenticated):
            issuer.login(**args)

    def test_concurrent_login_on_one_challenge_succeeds_once(self, auth):
        issuer, staff, pk_hex = auth
        args = self._login_args(issuer, staff, pk_hex)

        results: list[str] = []
        failures: list[Exception] = []
        start = threading.Barrier(8)

        def attempt():
            start.wait()
            try:
                results.append(issuer.login(**args)["token"])
            except Exception as exc:  # noqa: BLE001 - 统计失败类型
                failures.append(exc)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 1, f"并发登录成功了 {len(results)} 次"
        assert len(failures) == 7
        assert all(isinstance(e, Unauthenticated) for e in failures)

    def test_unknown_challenge_is_rejected(self, auth):
        """没经过 /challenge 的随机串，即使签名自洽也不能登录。"""
        issuer, staff, pk_hex = auth
        unknown = "de" * 24
        sig = v1.auth.sign_login(staff, challenge=unknown, aud=issuer.aud)
        with pytest.raises(Unauthenticated):
            issuer.login(challenge=unknown, sign_pk=pk_hex, sig=sig)
