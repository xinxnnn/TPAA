"""IPFS 方 + 加密信封测试。

五方齐了之后，这两者是配对出现的：
    envelope 负责"封"与"解"（TP 侧）
    storage-service 负责"存"与"取"（IPFS 侧）

★ 核心断言：IPFS 侧从头到尾只见密文，连 CID 都是被保护过的。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from services.ipfs.storage_service.storage_service import AccessRecord, StorageService  # noqa: E402

from crypto.envelope import (  # noqa: E402
    derive_key,
    protect_cid,
    recover_cid,
    seal_secinfo,
    unseal_secinfo,
)

BI = b"<iris+fingerprint template>"
PII = b'{"name":"Zhang San","id":"110101199003071234"}'
SEED = (b"rf-material-123", b"initial-key-factor")


def test_secinfo_roundtrip() -> None:
    """G2 打包 → R2 拆封，内容一致。"""
    key, nonce, ct, tag = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    out = unseal_secinfo(key=key, nonce=nonce, ciphertext=ct, tag=tag)
    assert out is not None
    assert out[0] == BI and out[1] == PII


def test_secinfo_ciphertext_is_not_plaintext() -> None:
    """信封里不能直接看到明文。"""
    _, _, ct, _ = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    assert BI not in ct and PII not in ct


def test_tampered_envelope_is_detected() -> None:
    """密文被改一个字节 → 拆封必须失败（完整性）。"""
    key, nonce, ct, tag = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    assert unseal_secinfo(key=key, nonce=nonce, ciphertext=bad, tag=tag) is None


def test_wrong_key_fails() -> None:
    """用错误的种子派生密钥去拆 → 失败。"""
    key, nonce, ct, tag = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    other = derive_key(b"rf-material-999", b"initial-key-factor", info=b"tpaa/secinfo/v1")
    assert unseal_secinfo(key=other, nonce=nonce, ciphertext=ct, tag=tag) is None


def test_g2_to_r2_full_path_through_ipfs() -> None:
    """完整链路：G2 封 → 上传 IPFS → 保护 CID → R2 取回 → 拆封。"""
    ipfs = StorageService()

    # ---- G2（TP 侧）----
    key, nonce, ct, tag = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    cid = ipfs.put(ct, requester="tp/phc-service")       # IPFS 只见密文
    ecid = protect_cid(cid, key)                          # CID 立即变 ECID

    # ---- R2（TP 侧）----
    recovered_cid = recover_cid(ecid, key)
    assert recovered_cid == cid, "ECID 必须能还原回 CID"
    ciphertext = ipfs.get(recovered_cid, requester="tp/supervision-service")
    out = unseal_secinfo(key=key, nonce=nonce, ciphertext=ciphertext, tag=tag)
    assert out == (BI, PII), "R2 必须还原出原始 BI/PII"


def test_cid_protection_hides_cid() -> None:
    """★ 红线 17：ECID 里不能出现 CID 的任何片段。"""
    key, _, _, _ = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    cid = "bafy" + "a" * 55
    ecid = protect_cid(cid, key)
    assert cid not in ecid
    assert recover_cid(ecid, b"wrong-key") is None


def test_ipfs_never_sees_keys_or_plaintext() -> None:
    """★ IPFS 方的自证：它那里没有密钥、没有明文。"""
    ipfs = StorageService()
    key, nonce, ct, tag = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)

    # 攻击者视角：直接翻 IPFS 的全部存储
    cid = ipfs.put(ct, requester="tp/phc-service")
    dumped = b"".join(ipfs._objects.values())
    assert BI not in dumped and PII not in dumped, "存储里不能有明文"
    assert key not in dumped, "存储里不能有密钥"

    sc = ipfs.self_check()
    assert sc["holds_keys"] is False


def test_ipfs_access_log_records_every_get() -> None:
    """★ 红线 18：每次取用必须留痕。"""
    ipfs = StorageService()
    key, _, ct, _ = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    cid = ipfs.put(ct, requester="tp/phc-service")

    ipfs.get(cid, requester="tp/supervision-service")
    ipfs.get(cid, requester="attacker")        # 未授权的取用也会被记录下来

    logs = ipfs.log_of(cid)
    gets = [r for r in logs if r.action == "get"]
    assert len(gets) == 2, "两次取用都要留痕"
    assert {r.requester for r in gets} == {"tp/supervision-service", "attacker"}
    assert all(isinstance(r, AccessRecord) for r in gets)


def test_pin_prevents_gc_semantically() -> None:
    """固定的对象可长期取回；未固定的不承诺。"""
    ipfs = StorageService()
    key, _, ct, _ = seal_secinfo(bi=BI, pii=PII, seed_parts=SEED)
    cid = ipfs.put(ct, requester="tp/phc-service")
    assert ipfs.pin(cid, requester="tp/phc-service")
    assert cid in ipfs._pinned
    assert ipfs.get(cid, requester="tp/phc-service") == ct
    assert not ipfs.pin("bafy-nonexistent", requester="someone")


def test_local_persistent_storage_keeps_only_ciphertext_and_access_log(tmp_path: Path) -> None:
    state_path = tmp_path / "objects.json"
    ciphertext = b"synthetic ciphertext only"
    first = StorageService(state_path=state_path)
    cid = first.put(ciphertext, requester="tp/phc-service")
    assert first.pin(cid, requester="tp/phc-service")

    restarted = StorageService(state_path=state_path)
    assert restarted.get(cid, requester="tp/supervision-service") == ciphertext
    assert restarted.log_of(cid)[-1].action == "get"
    assert restarted._pinned == {cid}
    assert b"synthetic identity" not in state_path.read_bytes()
