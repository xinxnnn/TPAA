"""协议记录落盘：往返不失真、大整数不截断、反序列化只认白名单类型。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tpaa_v1_protocol import shared, v1  # noqa: E402


def _raises(exc, fn):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"预期 {exc.__name__}")


def test_records_roundtrip_through_json() -> None:
    r = shared()
    for obj in (r.trec2, r.arec, r.pending, r.cred, r.verified):
        back = v1.records.load(json.loads(json.dumps(v1.records.dump(obj))))
        assert back == obj, type(obj).__name__


def test_big_ints_are_not_json_numbers() -> None:
    blob = json.dumps(v1.records.dump(shared().arec))
    assert '"$int"' in blob
    for v in json.loads(blob).values():
        assert not isinstance(v, (int, float)) or isinstance(v, bool)


def test_unknown_type_rejected_on_load_and_dump() -> None:
    _raises(TypeError, lambda: v1.records.load({"$type": "OpenedCR", "pii": {}}))
    _raises(TypeError, lambda: v1.records.load({"$type": "os.system"}))
    # ApSession 含 r_ap（只该在构建那一刻存在于内存里），也不在白名单里
    from crypto.tpaa_v1.proto_ap import ApSession
    _raises(TypeError, lambda: v1.records.dump(_dummy(ApSession)))


def test_opened_cr_with_plaintext_pii_cannot_be_persisted() -> None:
    """OpenedCR 带 BI/PII 明文，刻意不在白名单里：想落盘就会失败，而不是悄悄写进库。"""
    from crypto.tpaa_v1.proto_tp import OpenedCR
    _raises(TypeError, lambda: v1.records.dump(_dummy(OpenedCR)))


def _dummy(cls):
    from dataclasses import fields
    return cls(**{f.name: ({} if f.type == "dict" else 0 if f.type == "int" else "")
                  for f in fields(cls)})
