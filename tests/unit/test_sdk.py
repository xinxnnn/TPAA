"""验证：上层只 import crypto.sdk 即可完成协议动作（钉死 guard 的 R2 价值）。

本测试模拟"业务层"调用：不 import 任何 crypto 内部实现，只经 crypto.sdk。
（tests/ 在 guard 豁免名单内，但此处刻意不使用内部模块，证明 sdk 入口自足。）

★ 注意这里连一个原始密钥都没有：业务层拿到的只有 HSM 句柄，
  跨域给出去的只有 hsm.public_chameleon()，私钥与陷门一样都不露面。
"""

from __future__ import annotations

from crypto.sdk import (
    issue_phc,
    make_demo_hsm,
    seal_secinfo,
    unseal_secinfo,
    update_by_ap,
    update_by_tp,
    verify_phc,
)


def test_sdk_phc_issue_and_verify():
    """业务层经 crypto.sdk 走完 G3 → 算法1 → 算法2。"""
    tp = make_demo_hsm(domain="TP")
    ap = make_demo_hsm(domain="AP")

    phc = issue_phc(
        tp_hsm=tp,
        ap_ch=ap.public_chameleon(),     # 跨域只交公钥句柄
        identity_hash=12345,
        tau=1,
        crf=777,
        tpm_time="2026-10-14T00:00:00Z",
        tpm_ecid="ECID_demo",
    )
    update_by_ap(phc, ap_hsm=ap, cmi="c0ffee", apm_time="2026-10-14T00:01:00Z")
    update_by_tp(phc, tp_hsm=tp, did="did:wba:demo:pa.example")

    errs = verify_phc(
        phc,
        tp_pk=tp.pubkey(),
        ap_pk=ap.pubkey(),
        tp_ch=tp.public_chameleon(),
        ap_ch=ap.public_chameleon(),
        identity_hash=12345,
        tau=1,
        crf=777,
    )
    assert errs == [], errs


def test_sdk_public_handle_has_no_trapdoor():
    """★ 交出去的那份句柄改不了任何东西 —— 跨域那一方拿到也重写不了内容。"""
    ap = make_demo_hsm(domain="AP")
    pub = ap.public_chameleon()
    assert pub.has_trapdoor() is False
    assert not hasattr(pub, "_key"), "公开句柄里不该残留任何密钥对象"


def test_sdk_envelope_roundtrip():
    seed = b"16-byte-key-xxxx"
    # seal 返回的第一个值是派生后的实际密钥，unseal 必须用同一个 key
    key, nonce, ct, tag = seal_secinfo(bi=b"bio", pii=b"id", seed_parts=[seed])
    out = unseal_secinfo(key=key, nonce=nonce, ciphertext=ct, tag=tag)
    assert out == (b"bio", b"id")
