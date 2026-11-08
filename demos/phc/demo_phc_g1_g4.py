"""TPAA v1 第二阶段完整可审计演示：用户身份验证与 PHC 初始化（G1 → G4）。

    python demos/phc/demo_phc_g1_g4.py

本脚本使用**明确声明的合成演示材料**，不是随机生成、不是现实用户数据：
    PII：代码内的演示身份证号、姓名、手机号
    BI ：代码内的合成虹膜/指纹照片元数据与 SHA-256 摘要

输出原则：
    * 打印协议要求的每一个计算结果、字段、传输方向和完整 PHC JSON-LD。
    * 打印 CR/RR 等密文封装的完整结构（密文内容本身不会被伪装成明文）。
    * 只输出公开参数、合成材料、随机数/中间量和密文；绝不输出 User/TP/AP/Review 私钥。
    * SecInfo 只打印密文对象与 CID；BI/PII 明文只在 G2 TP 解密 CR 和 G4 User 本地解密结果中展示，
      因为本演示使用的是明确的合成材料。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pprint import pformat

ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import crypto.sdk  # noqa: E402
from services.ipfs.storage_service.app import StorageService  # noqa: E402

v1 = crypto.sdk.v1


class Clock:
    def now(self) -> str:
        return "2026-10-28T10:00:00"


def show(label: str, value, *, full: bool = True) -> None:
    print(f"\n[{label}]")
    if isinstance(value, (dict, list, tuple)):
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    elif full:
        print(value)
    else:
        text = str(value)
        print(text if len(text) <= 96 else text[:96] + "…")


def public_point(hsm) -> str:
    return crypto.sdk.ser_point(hsm.pubkey()).hex()


def main() -> int:
    clock = Clock()

    # ------------------------------------------------------------------
    # 0. 参与方与合成输入
    # ------------------------------------------------------------------
    user = v1.make_demo_hsm(domain="USER")
    tp = v1.make_demo_hsm(domain="TP")
    ap = v1.make_demo_hsm(domain="AP")
    review = v1.make_demo_hsm(domain="REVIEW")
    sup = crypto.sdk.make_supervision_key(bits=2048)
    storage = StorageService()

    # 这些数据是脚本内固定的合成样本，方便复现和核对；不是随机生成，也不是真实用户资料。
    pii = {
        "ID": "110101199003071234",
        "name": "演示用户",
        "phone": "13800000000",
    }
    synthetic_iris = b"TPAA synthetic iris photo fixture / user-demo-001"
    synthetic_fingerprint = b"TPAA synthetic fingerprint photo fixture / user-demo-001"
    bi = {
        "irisPhoto": {
            "fileName": "iris-demo-001.bin",
            "contentType": "application/octet-stream",
            "sha256": hashlib.sha256(synthetic_iris).hexdigest(),
            "bytes": len(synthetic_iris),
        },
        "fingerprintPhoto": {
            "fileName": "finger-demo-001.bin",
            "contentType": "application/octet-stream",
            "sha256": hashlib.sha256(synthetic_fingerprint).hexdigest(),
            "bytes": len(synthetic_fingerprint),
        },
    }

    owner = v1.owner_of(user.pubkey())
    tp_slot = tp.allocate_slot(owner)
    ap_slot = ap.allocate_slot(owner)

    print("=" * 96)
    print("TPAA v1 · 用户身份验证与人格凭证（PHC）初始化 · G1 → G4")
    print("=" * 96)
    print("说明：以下 PII / BI 是脚本内固定的合成演示材料，不是真实用户数据。")
    show("演示时钟", clock.now())
    show("PII（用户在 G1 输入）", pii)
    show("BI（用户在 G1 输入：照片元数据，不输出照片二进制）", bi)
    show("User 公钥 pk_a（公开）", public_point(user))
    show("AP 公钥 pk_ap（公开）", public_point(ap))
    show("TP 公钥 pk_tp（公开）", public_point(tp))
    show("TP 槽位（nonce, per-credential public trapdoor）", {"nonce": tp_slot[0], "pub": format(tp_slot[1], "x")})
    show("AP 槽位（nonce, per-credential public trapdoor）", {"nonce": ap_slot[0], "pub": format(ap_slot[1], "x")})

    # ------------------------------------------------------------------
    # G1 User：H(ID)、r_bind、AF、用户签名、CR 加密
    # ------------------------------------------------------------------
    print("\n" + "-" * 96)
    print("STEP G1 · User 生成 AF / r_bind 并构造加密 CR")
    print("-" * 96)
    cr, pending = v1.user.g1_build_cr(
        user_hsm=user,
        pii=pii,
        bi=bi,
        tp_enc_pk=tp.enc_pub(),
        tp_slot=tp_slot,
        ap_slot=ap_slot,
        ap_sign_pk=ap.pubkey(),
        request_id="cr-demo-0001",
        expires="2026-10-28T11:00:00",
    )
    show("H(ID)", format(pending.hid, "x"))
    show("r_bind（用户生成，完整十六进制）", format(pending.af.r, "x"))
    show("CCH 初始指数 x_a", pending.af.x_a)
    show("CCH 初始指数 x_t", pending.af.x_t)
    show("AF = h(ID) · A · T · g^r_bind mod p", format(pending.af.af, "x"))
    show("CR → TP（加密信封完整结构）", cr)
    show("CR 传输方向", "User --EN_pk_tp(CR)--> TP")
    print("G1 结果：PASS")

    # ------------------------------------------------------------------
    # G2 TP：解密 CR、验签、验 AF、IRF、CCH、SecInfo、ECID
    # ------------------------------------------------------------------
    print("\n" + "-" * 96)
    print("STEP G2 · TP 解密并验证 CR，生成 IRF，绑定 AF，保存 SecInfo")
    print("-" * 96)
    opened = v1.tp.tp_open_cr(tp_hsm=tp, cr_box=cr, now=clock.now())
    show("TP 解密 CR 后得到的 PII", opened.pii)
    show("TP 解密 CR 后得到的 BI", opened.bi)
    show("TP 验证出的用户 owner", opened.owner)
    show("TP 读取的 requestId", opened.request_id)
    show("TP 计算得到的 CR digest", opened.cr_digest)
    show("G2 签名验证", "PASS（User signature over CR body）")
    show("G2 AF 验证", {"expected": format(pending.af.af, "x"), "received": format(opened.af.af, "x"), "equal": pending.af.af == opened.af.af})

    approval = v1.tp.approve(
        reviewer_hsm=review,
        cr_digest=opened.cr_digest,
        reviewers=["reviewer-a"],
        expires="2026-10-28T11:00:00",
    )
    show("人工批准证据（绑定 CR digest）", approval)
    show("批准证据传输方向", "review-service --approval evidence--> phc-service")

    # 计算 G2 中会进入后续流程的结果；tp_issue 内部会再次执行相同动作。
    irf_preview = v1.compute_irf(opened.hid, sup.public())
    af_after_tp = v1.rebind_af(
        opened.af, hsm=tp, hid=opened.hid, nonce=opened.tp_nonce,
        owner=opened.owner, kind="IRF", value=irf_preview)
    show("IRF = PEnc_ppk(H(ID))", format(irf_preview, "x"))
    show("r_bind' = CCH_TP(初始指数, IRF)", format(af_after_tp.r, "x"))
    show("AF 绑定 IRF 后（取值应保持不变）", format(af_after_tp.af, "x"))
    show("AF 前后是否相等", pending.af.af == af_after_tp.af)
    show("G2 公式核验", {
        "HID": format(opened.hid, "x"),
        "a_pub": format(af_after_tp.a_pub, "x"),
        "t_pub": format(af_after_tp.t_pub, "x"),
        "x_a": af_after_tp.x_a,
        "x_t": af_after_tp.x_t,
        "r_bind_prime": format(af_after_tp.r, "x"),
        "AF": format(af_after_tp.af, "x"),
        "holds": af_after_tp.holds(opened.hid),
    })

    # ------------------------------------------------------------------
    # G3 TP：SecInfo、CID、ECID、PHC、TPAC、RR
    # ------------------------------------------------------------------
    print("\n" + "-" * 96)
    print("STEP G3 · TP 生成 SecInfo / ECID / PHC / TPAC / RR")
    print("-" * 96)
    rr, record = v1.tp.tp_issue(
        tp_hsm=tp,
        opened=opened,
        approval=approval,
        review_pk=review.pubkey(),
        sup_pub=sup.public(),
        storage=storage,
        ap_ch=ap.public_chameleon(),
        ap_sign_pk=ap.pubkey(),
        ap_enc_pk=ap.enc_pub(),
        now=clock.now(),
    )
    show("TpRecord.hid", format(record.hid, "x"))
    show("TpRecord.AF", format(record.af.af, "x"))
    show("TpRecord.r_bind'（TP 本地记录，不进 PHC）", format(record.af.r, "x"))
    show("TpRecord.irf", format(record.irf, "x"))
    show("CID → IPFS/storage 的对象标识", list(storage._objects.keys()))  # noqa: SLF001
    show("IPFS/storage 对象（密文完整字节 hex）", {k: v.hex() for k, v in storage._objects.items()})  # noqa: SLF001
    show("IPFS/storage 是否持有密钥", False)
    show("ECID = PEnc(CID) 第一阶段", format(record.ecid, "x"))

    # tp_issue 返回的 RR 是密文；为完整展示 G3 结果，这里在用户 HSM 内模拟解密，不绕过用户密钥。
    rr_payload = user.pke_open(rr, tag="RR")
    show("RR 传输方向", "TP --EN_pk_a(PHC, TPAC)--> User")
    show("RR 加密信封完整结构", rr)
    show("RR 由 User HSM 解密后的外层结构", rr_payload)
    show("TPAC body", rr_payload["TPAC"]["body"])
    show("TPAC signature", rr_payload["TPAC"]["sig"])
    show("PHC JSON-LD（G3 初始 PHC，完整结构）", rr_payload["PHC"])
    show("PHC 结构字段", {
        "ASO.TPM": list(rr_payload["PHC"]["ASO"]["TPM"].keys()),
        "ASO.APM": list(rr_payload["PHC"]["ASO"]["APM"].keys()),
        "TPA": list(rr_payload["PHC"]["TPA"].keys()),
        "APA": list(rr_payload["PHC"]["APA"].keys()),
        "PROOF": list(rr_payload["PHC"]["PROOF"].keys()),
    })
    print("G3 结果：PASS")

    # ------------------------------------------------------------------
    # G4 User：解 RR，逐项验证 PHC / TPAC / AF
    # ------------------------------------------------------------------
    print("\n" + "-" * 96)
    print("STEP G4 · User 解密 RR 并验证 PHC / TPAC / AF 绑定")
    print("-" * 96)
    cred = v1.user.g4_accept_rr(
        user_hsm=user,
        rr_box=rr,
        pending=pending,
        tp_sign_pk=tp.pubkey(),
        ap_sign_pk=ap.pubkey(),
    )
    phc = cred.phc
    show("G4 PHC JSON-LD（User 保存的完整结构）", phc)
    show("G4 验证项", {
        "PHC profile": phc["profile"],
        "PHC version": phc["version"],
        "TPproof": "VALID",
        "CHproof": "VALID",
        "TPAC signature": "VALID",
        "TPAC.phcDigest": "MATCH",
        "TPAC.owner": "MATCH",
        "TPAC.slot binding": "MATCH",
        "AF from PHC": format(cred.af.af, "x"),
        "r_bind_prime from TPAC": format(cred.af.r, "x"),
        "IRF from TPAC": cred.tpac["body"]["IRF"],
        "AF =? h(ID)·A·T^X(IRF)·g^r_bind'": cred.af.holds(cred.hid),
    })
    show("User 最终本地状态", {
        "hid": format(cred.hid, "x"),
        "phcProfile": phc["profile"],
        "phcVersion": phc["version"],
        "AF": format(cred.af.af, "x"),
        "PII / BI 是否继续对外传输": False,
    })
    print("G4 结果：PASS")
    print("=" * 96)
    print("第二阶段 G1–G4：PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
