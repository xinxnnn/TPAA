"""localstore 测试：目录契约、只读模块、读取即校验、身份索引加密、软删隔离。

这里全部用**临时目录**做根 —— 真实的 localstore 根在部署时是挂载卷，
测试往里写东西会把「取证现场」搞脏。
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import localstore as LS
from localstore.paths import encode_agent_id

DID_ROOT = "did:wba:ROOT:pa.example"
DID_SUB = "did:wba:ROOT:pa.example:sub-1"
HID = "ab" * 32


def _layout() -> LS.Layout:
    d = tempfile.mkdtemp(prefix="ls-")
    lay = LS.Layout(d)
    lay.ensure_base()
    return lay


def _key() -> bytes:
    return b"k" * 32


# ---------------------------------------------------------------------------
# 路径契约：派生链不能把父体拖进子体目录
# ---------------------------------------------------------------------------


def test_agent_dir_is_flat_for_parent_and_child() -> None:
    """★ 子体 DID 以父体 DID 为前缀 —— 目录必须扁平，否则删子体等于删父体整棵树。"""
    lay = _layout()
    p = lay.agent_dir(DID_ROOT)
    c = lay.agent_dir(DID_SUB)
    assert p.parent == c.parent, "父子实例必须同层"
    assert p != c


def test_encode_rejects_traversal() -> None:
    for bad in ("", "did:", "did:a b", "not-a-did", "did:.."):
        try:
            encode_agent_id(bad)
        except LS.StoreLayoutError:
            continue
        raise AssertionError(f"应拒绝非法 DID：{bad!r}")


# ---------------------------------------------------------------------------
# 模块仓库：内容寻址、禁止原地改写、只读
# ---------------------------------------------------------------------------


def test_module_publish_is_idempotent_and_immutable() -> None:
    lay = _layout()
    repo = LS.ModuleRepo(lay)
    e1 = repo.publish("planner", "1.0.0", {"engine.py": b"print(1)"})
    e2 = repo.publish("planner", "1.0.0", {"engine.py": b"print(1)"})
    assert e1.digest == e2.digest

    try:
        repo.publish("planner", "1.0.0", {"engine.py": b"print(2)"})
    except LS.StoreLayoutError as e:
        assert "原地改写" in str(e)
    else:
        raise AssertionError("同一版本号不得改写内容")


def test_module_tamper_detected_on_read() -> None:
    lay = _layout()
    repo = LS.ModuleRepo(lay)
    repo.publish("planner", "1.0.0", {"engine.py": b"print(1)"})
    f = lay.module_dir("planner", "1.0.0") / "engine.py"
    f.chmod(0o644)                       # 绕过只读位，模拟磁盘层篡改
    f.write_bytes(b"print(9)")
    try:
        repo.read_file("planner", "1.0.0", "engine.py")
    except LS.StoreLayoutError as e:
        assert "篡改" in str(e)
    else:
        raise AssertionError("篡改后读取必须失败")


def test_module_revoke_keeps_files() -> None:
    lay = _layout()
    repo = LS.ModuleRepo(lay)
    repo.publish("planner", "1.0.0", {"engine.py": b"x"})
    repo.revoke("planner", "1.0.0")
    assert repo.get_entry("planner", "1.0.0").revoked is True
    assert (lay.module_dir("planner", "1.0.0") / "engine.py").exists(), "下架不删文件"


# ---------------------------------------------------------------------------
# 读取即校验（红线 15）
# ---------------------------------------------------------------------------


def _make_instance(lay: LS.Layout, cmi: str = "aa" * 32) -> LS.AgentStore:
    store = LS.AgentStore(lay)
    store.save_meta(LS.AgentMeta(
        did=DID_ROOT, agent_type=LS.AgentType.PRIMARY, owner_did=DID_ROOT,
        identity_hash=HID, created_at="2026-10-26T00:00:00"))
    store.save_cmi(DID_ROOT, LS.CmiRecord(cmi=cmi, layers=["l1"], computed_at="t"))
    return store


def test_cmi_mismatch_freezes_instance() -> None:
    """★ 校验不通过只有一种处置：冻结 + 告警，不做自动修复。"""
    lay = _layout()
    store = _make_instance(lay, cmi="aa" * 32)
    try:
        LS.assert_cmi_matches(store, DID_ROOT, "bb" * 32, at="2026-10-26T01:00:00")
    except LS.GuardViolation as e:
        assert e.expected == "bb" * 32
    else:
        raise AssertionError("CMI 不一致必须抛错")

    meta = store.load_meta(DID_ROOT)
    assert meta.state is LS.AgentState.FROZEN
    assert "CMI" in meta.frozen_reason


def test_cmi_match_leaves_state() -> None:
    lay = _layout()
    store = _make_instance(lay, cmi="aa" * 32)
    LS.assert_cmi_matches(store, DID_ROOT, "aa" * 32, at="t")
    assert store.load_meta(DID_ROOT).state is LS.AgentState.ACTIVE


def test_frozen_instance_is_not_deleted() -> None:
    """冻结保留现场：只是状态变了，文件都在。"""
    lay = _layout()
    store = _make_instance(lay)
    store.freeze(DID_ROOT, "test", at="t")
    assert lay.agent_meta(DID_ROOT).exists()
    assert (lay.agent_dir(DID_ROOT) / "cmi.json").exists()


# ---------------------------------------------------------------------------
# 级联：按 parent_did 扫，逐层冻，不删
# ---------------------------------------------------------------------------


def _add(store: LS.AgentStore, did: str, parent: str = "") -> None:
    store.save_meta(LS.AgentMeta(
        did=did, agent_type=LS.AgentType.SUB if parent else LS.AgentType.PRIMARY,
        owner_did=DID_ROOT, identity_hash=HID, created_at="t", parent_did=parent))


def test_cascade_freezes_grandchildren() -> None:
    lay = _layout()
    store = _make_instance(lay)
    _add(store, DID_SUB, DID_ROOT)
    _add(store, DID_SUB + ":g1", DID_SUB)
    _add(store, "did:wba:ROOT:pa.example:other", DID_ROOT)

    frozen = LS.cascade_freeze(store, DID_ROOT, at="t", reason="父体吊销")
    # 父体的其它分支也要冻 —— 级联按「谁的父体被吊销」判断，不按命名空间前缀
    assert set(frozen) == {
        DID_SUB, DID_SUB + ":g1", "did:wba:ROOT:pa.example:other",
    }
    assert store.load_meta(DID_ROOT).state is LS.AgentState.ACTIVE, "根体本身不由级联冻结"
    assert store.load_meta(DID_SUB + ":g1").state is LS.AgentState.FROZEN, "孙代也要冻"
    assert lay.agent_meta(DID_SUB).exists(), "冻结不删除"


# ---------------------------------------------------------------------------
# 身份索引：必须加密，且要能发现拿错密钥
# ---------------------------------------------------------------------------


def test_identity_index_is_not_plaintext() -> None:
    """★ 全目录唯一含身份映射的文件，落盘不得出现 H(ID) 明文。"""
    lay = _layout()
    idx = LS.IdentityIndex(lay)
    idx.add(HID, DID_ROOT, sealer=idx.sealer(_key()), opener=idx.opener(_key()))
    raw = lay.identity_index.read_text(encoding="utf-8")
    assert HID not in raw
    assert "did-wba" not in raw and DID_ROOT not in raw


def test_identity_index_wrong_key_rejected() -> None:
    lay = _layout()
    idx = LS.IdentityIndex(lay)
    idx.add(HID, DID_ROOT, sealer=idx.sealer(_key()), opener=idx.opener(_key()))
    other = b"x" * 32
    try:
        idx.lookup(HID, opener=idx.opener(other))
    except LS.index.IndexCorrupted:
        return
    raise AssertionError("拿错密钥必须报错，不得返回空列表")


def test_identity_index_multi_agent_per_person() -> None:
    """一个人名下可以有多个智能体（主 + 子），找回要能一次列全。"""
    lay = _layout()
    idx = LS.IdentityIndex(lay)
    k = _key()
    idx.add(HID, DID_ROOT, sealer=idx.sealer(k), opener=idx.opener(k))
    idx.add(HID, DID_SUB, sealer=idx.sealer(k), opener=idx.opener(k))
    assert idx.lookup(HID, opener=idx.opener(k)) == sorted([DID_ROOT, DID_SUB])

    idx.remove(HID, DID_SUB, sealer=idx.sealer(k), opener=idx.opener(k))
    assert idx.lookup(HID, opener=idx.opener(k)) == [DID_ROOT]


# ---------------------------------------------------------------------------
# 软删
# ---------------------------------------------------------------------------


def test_recycle_moves_whole_subtree() -> None:
    lay = _layout()
    store = _make_instance(lay)
    (lay.agent_dir(DID_ROOT) / "build" / "1").mkdir(parents=True)
    (lay.agent_dir(DID_ROOT) / "build" / "1" / "agent.yaml").write_text("x", encoding="utf-8")

    LS.place_in_recycle(lay, store, DID_ROOT, at="t")
    assert not lay.agent_dir(DID_ROOT).exists()
    assert (lay.recycled(DID_ROOT) / "build" / "1" / "agent.yaml").exists()
    # 回收后不能再次出现在正常枚举里
    assert store.iter_all() == []


def test_iter_all_reads_only_meta() -> None:
    lay = _layout()
    store = _make_instance(lay)
    _add(store, DID_SUB, DID_ROOT)
    metas = store.iter_all()
    assert {m.did for m in metas} == {DID_ROOT, DID_SUB}
    # meta 里不得出现身份明文
    raw = lay.agent_meta(DID_ROOT).read_text(encoding="utf-8")
    assert json.loads(raw)["identity_hash"] == HID
    assert "110101" not in raw
