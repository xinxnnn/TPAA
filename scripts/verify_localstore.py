#!/usr/bin/env python
"""localstore 巡检：把一个**已经在跑**的库逐实例验一遍。

    python scripts/verify_localstore.py                       # 用环境变量里的配置
    python scripts/verify_localstore.py --root ./localstore   # 指定目录（仍需密钥环境变量）
    python scripts/verify_localstore.py --json                # 机器可读（给告警/监控喂）
    python scripts/verify_localstore.py --freeze              # 发现问题就冻结（默认只报告）

它和 `run_tests.py` 里那些用例的区别：
    用例验的是"代码对不对"，本脚本验的是"**这个库现在还好不好**"。
    库会被人改、被磁盘损坏、被半截写入。所以它必须能独立于测试、在生产上跑。

四类判据（逐项对应协议里的承诺）：

    1. 结构     meta / selection / cmi / phc / versions / build 是否齐备、索引里有没有登记
    2. 凭证     PHC 用**公开材料**验签（签名、AF 锚定、APCH/TPCH 完整性）
    3. 一致性   本地重算的 CMI == cmi.json == PHC.APM.CMI
    4. 交付性   build 里的 buildDigest == versions.json 记的那个

★ 为什么默认**不**动手：
  这个脚本最常被用在"查一下现在什么情况"。一个查的时候顺手改状态的工具，
  没人敢在出事的时候用它 —— 因为分不清看到的是现场还是它自己造成的。
  要处置请显式加 `--freeze`，它只冻结（保留取证），永不删除。

★ 为什么它需要密钥环境变量：
  身份索引是加密的（全库唯一含身份映射的文件）。要判断"这个实例还挂在它主人名下"，
  就必须解得开索引 —— 拿不到密钥时脚本**拒绝运行**，而不是跳过了事：
  一个静默跳过了最关键一项的巡检报告，比没有报告更危险。
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# agent-service 的目录名带连字符。作为**模块名字符串**是合法的
# （importlib 按名字找目录，不要求是标识符）。统一从这里取，避免各处各写一遍。
_SVC = "services.ap_side.agent_service"


def svc(name: str):
    return importlib.import_module(f"{_SVC}.{name}")


def load_hsms(path: str | None):
    """取得 TP / AP 的一对 HSM 句柄。

    演练环境：`--hsms seed.json`，文件里是两对私钥标量（`{"tp": {...}, "ap": {...}}`）。
    没有给就用随机的一对 —— 这时脚本仍能查"结构/一致性/交付"，但**凭证那项会失败**，
    所以会打一条醒目告警，让人知道那批失败是"验不了"而不是"验不过"。

    生产环境：把这里换成真实 HSM/KMS 的句柄获取方式（同一个函数、同一个返回形态）。
    """
    import crypto.sdk

    if not path:
        print("! 未提供 --hsms：本次使用随机 HSM，凭证校验结果不可信（只反映结构/一致性）",
              file=sys.stderr)
        return (crypto.sdk.make_demo_hsm(domain="TP"),
                crypto.sdk.make_demo_hsm(domain="AP"))

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    def mk(domain: str, node: dict):
        return crypto.sdk.make_demo_hsm(
            domain=domain,
            schnorr_sk=int(node["schnorr_sk"], 16) if node.get("schnorr_sk") else None,
            chameleon_sk=int(node["chameleon_sk"], 16) if node.get("chameleon_sk") else None,
        )
    return mk("TP", data["tp"]), mk("AP", data["ap"])


# ---------------------------------------------------------------------------
# 结果模型
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    did: str
    check: str                 # structure / credential / consistency / deliverable
    level: str                 # ok / warn / fail
    message: str

    def to_dict(self) -> dict:
        return {"did": self.did, "check": self.check,
                "level": self.level, "message": self.message}


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    frozen: list[str] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def failures(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "fail"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "warn"]

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "scanned": len(self.scanned),
            "frozen": self.frozen,
            "failures": [f.to_dict() for f in self.failures],
            "warnings": [f.to_dict() for f in self.warnings],
        }


# ---------------------------------------------------------------------------
# 四项判据
# ---------------------------------------------------------------------------


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def check_structure(ctx, did: str) -> tuple[list[Finding], bool]:
    """返回 (发现, 是否足以继续往下查)。"""
    out: list[Finding] = []
    d = ctx.layout.agent_dir(did)

    required = ("meta.json", "selection.json", "cmi.json", "phc.json", "versions.json")
    missing = [n for n in required if not (d / n).is_file()]
    if missing:
        out.append(Finding(did, "structure", "fail",
                           f"缺少文件：{', '.join(missing)}"))
        return out, False

    builds = [p for p in (d / "build").iterdir() if p.is_dir()] if (d / "build").is_dir() else []
    if not builds:
        out.append(Finding(did, "structure", "fail", "build/ 缺失或为空 —— 无从拉起"))
        return out, False

    if not ctx.identity_index.find_by_did(did, opener=ctx.opener()):
        # 不在索引里 = 没有"按身份找得到"的路径，等于原主丢了这个智能体
        out.append(Finding(did, "structure", "fail",
                           "未登记在身份索引中 —— 原主将无法找回它"))
        return out, False

    return out, True


def check_credential(ctx, did: str, *, tau: int, crf: int) -> tuple[list[Finding], str]:
    """验 PHC。返回 (发现, H(ID))。"""
    out: list[Finding] = []
    phc = _load_json(ctx.layout.agent_dir(did) / "phc.json")
    hid = ctx.identity_index.find_by_did(did, opener=ctx.opener())

    res = ctx.capability.verify_phc(phc, identity_hash=int(hid, 16), tau=tau, crf=crf)
    if not res.ok:
        out.append(Finding(did, "credential", "fail",
                           "PHC 校验未通过：" + "；".join(res.errors)))
        return out, hid

    cdid = phc.get("ASO", {}).get("TPM", {}).get("CDID", "")
    if cdid and cdid != did:
        out.append(Finding(did, "credential", "fail",
                           f"凭证 CDID（{cdid}）与目录 DID 不一致"))
        return out, hid

    # CMI 只有在算法1 跑过之后才非空。为空说明签发后 AP 那一步没做完：
    # 凭证本身验得过，但它承诺的配置是空的 —— 这是半成品，不能交付。
    if not phc.get("ASO", {}).get("APM", {}).get("CMI"):
        out.append(Finding(did, "credential", "fail",
                           "APM.CMI 为空 —— 算法1 未完成，凭证未承诺配置"))
        return out, hid

    return out, hid


def check_consistency(ctx, did: str) -> tuple[list[Finding], bool]:
    """三方一致：本地重算 == cmi.json == PHC.APM.CMI。"""
    out: list[Finding] = []
    compute_cmi = svc("domain.services.cmi").compute_cmi

    phc_cmi = _load_json(ctx.layout.agent_dir(did) / "phc.json")["ASO"]["APM"]["CMI"]
    local = ctx.agents.load_cmi(did)

    items = ctx.agents.load_selection(did).normalized()
    resolved = []
    for item in items:
        mid, ver = item["module_id"], item["version"]
        try:
            entry = ctx.modules.get_entry(mid, ver)
        except FileNotFoundError:
            out.append(Finding(did, "consistency", "fail",
                               f"模块缺失：{mid}@{ver} —— build 无法重建"))
            return out, False
        bad = ctx.modules.verify(mid, ver)
        if bad:
            out.append(Finding(did, "consistency", "fail",
                               f"模块仓库完整性受损：{mid}@{ver}（{bad[0]}）"))
            return out, False
        resolved.append((mid, ver, entry.digest))

    recomputed = compute_cmi(resolved)

    if recomputed.value != local.cmi:
        out.append(Finding(did, "consistency", "fail",
                           f"重算 CMI（{recomputed.value[:16]}…）与 cmi.json"
                           f"（{local.cmi[:16]}…）不一致 —— selection 或模块被换过"))
        return out, False
    if local.cmi != phc_cmi:
        out.append(Finding(did, "consistency", "fail",
                           f"cmi.json（{local.cmi[:16]}…）与凭证承诺"
                           f"（{phc_cmi[:16]}…）不一致"))
        return out, False

    return out, True


def check_deliverable(ctx, did: str) -> list[Finding]:
    """buildDigest 必须与 versions.json 记的那个一致。

    ★ 直接**从磁盘重算**，而不是读 build/1/integrity.json 里的某个字段：
      integrity.json 记的是 bundleDigest（内容摘要），不是 buildDigest，
      口径不同；而且它本身是"被检查的对象"，拿它当判据就成了自证。
      重算规则与 `BuildPlan.build_digest()` 一致：按相对路径排序，
      逐文件混入 `路径\\0内容\\0`。这里刻意**重写一遍**而不复用那个函数 ——
      巡检要能发现"build 被改过"，它就必须独立于构建代码。
    """
    import hashlib

    out: list[Finding] = []
    d = ctx.layout.agent_dir(did)
    versions = ctx.agents.load_versions(did)
    if not versions:
        out.append(Finding(did, "deliverable", "fail", "versions.json 为空"))
        return out

    latest = max(versions, key=lambda v: int(v.get("version", 0)))
    want = str(latest.get("buildDigest", ""))
    vdir = d / "build" / str(latest.get("version"))

    if not want:
        out.append(Finding(did, "deliverable", "warn",
                           "versions.json 未记录 buildDigest —— 无法校验交付一致性"))
        return out
    if not vdir.is_dir():
        out.append(Finding(did, "deliverable", "fail",
                           f"versions 指向 build/{vdir.name}，但该目录不存在"))
        return out

    h = hashlib.sha256()
    for p in sorted(x for x in vdir.rglob("*") if x.is_file()):
        h.update(p.relative_to(vdir).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    got = h.hexdigest()

    if got != want:
        out.append(Finding(did, "deliverable", "fail",
                           f"buildDigest 不一致：versions 记 {want[:16]}…，"
                           f"磁盘重算 {got[:16]}… —— build/ 被绕过平台改过"))
    return out


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TPAA localstore 巡检")
    ap.add_argument("--root", default=os.environ.get("TPAA_STORE_ROOT", ""),
                    help="localstore 根目录（默认取 TPAA_STORE_ROOT）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--hsms", default=os.environ.get("TPAA_HSM_SEED", ""),
                    help="TP/AP HSM 种子文件（演练用）；不给则凭证校验不可信")
    ap.add_argument("--freeze", action="store_true",
                    help="发现问题时冻结对应实例（只冻结，永不删除）")
    args = ap.parse_args(argv)

    if not args.root:
        print("缺少 --root 或环境变量 TPAA_STORE_ROOT", file=sys.stderr)
        return 2
    for name in ("TPAA_INDEX_KEY", "TPAA_ECID_KEY"):
        if not os.environ.get(name):
            print(f"缺少环境变量 {name}：巡检需要解开身份索引，否则无法判断"
                  f"实例是否仍挂在原主名下 —— 宁可拒绝运行，也不出一份漏检的报告",
                  file=sys.stderr)
            return 2

    # ★ 必须走 from_env + build_context，**不能**用 build_dev_context：
    #   后者会给每次调用随机生成 HSM 与密钥 —— 拿它来巡检，
    #   所有凭证都会报"验签失败、索引解不开"，而那全是假警报。
    #   巡检的价值全在"能看见真的问题"，所以宁可在这里多写两行。
    #
    # ★ 同理，HSM 也必须是**建库时那一对**。TP 的签名只认它自己的私钥，
    #   换一对 HSM 去验，全部凭证都会失败。演练环境下由 `--hsms` 指定一个
    #   能重建同一对 HSM 的种子文件；生产环境这里换成真实 HSM/KMS 句柄。
    infra = svc("infra.wiring")
    config = infra.InfraConfig.from_env({**os.environ, "TPAA_STORE_ROOT": args.root})
    tp_hsm, ap_hsm = load_hsms(args.hsms or None)
    ctx = infra.build_context(config=config, tp_hsm=tp_hsm, ap_hsm=ap_hsm,
                              storage=None)
    report = Report()

    for meta in ctx.agents.iter_all():
        report.scanned.append(meta.did)
        findings, ok = check_structure(ctx, meta.did)
        for f in findings:
            report.add(f)
        if not ok:
            continue

        findings, hid = check_credential(
            ctx, meta.did,
            tau=int(ctx.policy.get("tau", 1)), crf=int(ctx.policy.get("crf", 1)))
        for f in findings:
            report.add(f)
        if findings:
            continue

        findings, ok = check_consistency(ctx, meta.did)
        for f in findings:
            report.add(f)
        if not ok:
            continue

        for f in check_deliverable(ctx, meta.did):
            report.add(f)

    if args.freeze:
        for f in report.failures:
            if f.level == "fail" and f.did not in report.frozen:
                ctx.agents.freeze(f.did, f"巡检失败：{f.message}", at=ctx.clock.now())
                report.frozen.append(f.did)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"扫描 {len(report.scanned)} 个实例")
        for f in report.findings:
            tag = {"fail": "✗", "warn": "!", "ok": "✓"}[f.level]
            print(f"  {tag} [{f.check}] {f.did}\n      {f.message}")
        if report.frozen:
            print(f"\n已冻结 {len(report.frozen)} 个实例（未删除，保留取证）：")
            for did in report.frozen:
                print(f"  - {did}")
        if report.ok:
            print("\n全部通过。" if not report.warnings else
                  f"\n无致命问题（{len(report.warnings)} 项告警）。")
        else:
            print(f"\n{len(report.failures)} 项失败"
                  f"{'，已冻结' if report.frozen else '（未冻结，加 --freeze 处置）'}。")

    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
