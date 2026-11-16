"""Issued-agent conversation state is independent from MemAuth memory."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from localstore.delivery import directory
from packages.tpaa_runtime.local_state import LocalConversationState


OWNER = "owner-test"


def state(root, application_id):
    return LocalConversationState(directory(root, application_id), application_id=application_id,
                                  did=f"did:wba:{application_id}", owner=OWNER)


def test_separate_applications_and_reopen(tmp_path):
    with state(tmp_path, "first") as first:
        first.append("private to first", "first answer")
    with state(tmp_path, "second") as second:
        assert second.history() == []
        second.append("private to second", "second answer")
    with state(tmp_path, "first") as first:
        assert first.history() == [("private to first", "first answer")]
    with state(tmp_path, "second") as second:
        assert second.history() == [("private to second", "second answer")]


def test_failure_rolls_back_turn_and_identity(tmp_path):
    with pytest.raises(RuntimeError, match="model failed"):
        with state(tmp_path, "first") as first:
            first.append("failed question", "incomplete answer")
            raise RuntimeError("model failed")
    with state(tmp_path, "first") as first:
        assert first.history() == []
        first.append("successful question", "successful answer")
    with state(tmp_path, "first") as first:
        assert first.history() == [("successful question", "successful answer")]


def test_identity_mismatch_rejected_without_changing_history(tmp_path):
    with state(tmp_path, "first") as first:
        first.append("original", "answer")
    agent_dir = directory(tmp_path, "first")
    for identity in ({"application_id": "other", "did": "did:wba:first", "owner": OWNER},
                     {"application_id": "first", "did": "did:wba:other", "owner": OWNER},
                     {"application_id": "first", "did": "did:wba:first", "owner": "other"}):
        with pytest.raises(ValueError, match="归属"):
            with LocalConversationState(agent_dir, **identity):
                pytest.fail("mismatched identity opened state")
    with state(tmp_path, "first") as first:
        assert first.history() == [("original", "answer")]


def test_same_agent_turns_serialize_and_other_agent_is_independent(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    def first_turn():
        with state(tmp_path, "first") as first:
            first.append("one", "answer one")
            entered.set()
            assert release.wait(10)

    def second_turn():
        assert entered.wait(10)
        with state(tmp_path, "first") as first:
            previous = first.history()
            first.append("two", "answer two")
            return previous

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(first_turn)
        two = pool.submit(second_turn)
        assert entered.wait(10)
        with state(tmp_path, "second") as independent:
            independent.append("separate", "answer")
        release.set()
        one.result(timeout=15)
        assert two.result(timeout=15) == [("one", "answer one")]
    with state(tmp_path, "first") as first:
        assert first.history() == [("one", "answer one"), ("two", "answer two")]
