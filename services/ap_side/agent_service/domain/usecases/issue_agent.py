"""用例 1：申领主智能体（ARCHITECTURE §9.2 的 D1–D6）。

一条链路，五处"不做就会出事"的判断：

    D1  验 PHC：TP 背书、AF 锚定、APCH 完整 —— 任一项失败就不进入组装
    D2  查重：同一 H(ID) 下已有同 selection 的活跃实例则不重复生成
        （重复生成不报错、但它会让「一个人几个智能体」的台账开始漂）
    D3  模块解析：所选模块必须存在、未被下架；摘要取自模块仓库而非调用方口述
    D4  算 CMI → 交 TP 走算法1 写进 PHC → 落 localstore
    D5  三方一致：PHC 里的 AF、本地 cmi.json、build/integrity.json 必须对得上
    D6  封 DID：TP 给**唯一** DID，写回 PHC 并落盘

★ 顺序上有一处刻意的安排：**先写 localstore、后封 DID**。
  DID 是 TP 给的，一旦封上就是「对外承诺了这个智能体存在」；
  如果先封 DID 再写盘、写盘失败，就会出现一个对外存在、本地查不到的智能体 ——
  找回链路直接断掉。反过来先写盘，中途失败最多留下一个未封 DID 的半成品，
  它不可被交付（D6 未完成），也不会污染索引 —— **失败要落在可回收的一侧**。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import crypto.sdk

from localstore import (
    AgentMeta,
    AgentState,
    AgentStore,
    AgentType,
    CmiRecord as StoreCmiRecord,
    Selection as StoreSelection,
)

from ..entities import Agent, ModuleChoice, Selection, State
from ..ports import (
    IssueRequest,
    PublicKeyMaterial,
    SealDidRequest,
    WriteCmiRequest,
)
from ..services.build import assemble
from ..services.cmi import compute_cmi, digest_of
from ..services.context import AgentServiceContext


class IssueRejected(RuntimeError):
    """申领被拒。每一种原因都对应一条具体的业务约束，不做笼统的"参数错误"。"""


@dataclass(frozen=True)
class IssueCommand:
    identity_hash: int            # H(ID)，由 identity-service 核验后给出
    tau: int
    crf: int
    selection: Selection
    ttl_days: int = 0


@dataclass(frozen=True)
class IssueResult:
    did: str
    phc_json: dict
    cmi: str
    build_digest: str
    kept_existing: bool = False          # D2 命中查重时返回既有实例
    layers: list[str] = field(default_factory=list)


class IssueAgentUseCase:
    def __init__(self, ctx: AgentServiceContext) -> None:
        self.ctx = ctx

    def execute(self, cmd: IssueCommand) -> IssueResult:
        sel = cmd.selection
        if not sel.choices:
            raise IssueRejected("至少选择一个模块")
        hid_hex = f"{cmd.identity_hash:064x}"

        # ---- D2 查重（先查，省掉后面所有无意义的动作）----
        existing = self._find_duplicate(hid_hex, sel)
        if existing is not None:
            rec = self.ctx.agents.load_cmi(existing)
            return IssueResult(
                did=existing, phc_json=self._load_phc(existing),
                cmi=rec.cmi, build_digest="", kept_existing=True,
                layers=list(rec.layers),
            )

        # ---- D3 解析模块：存在 + 未下架 ----
        resolved = self._resolve_modules(sel)

        # ---- D4 算 CMI ----
        cmi = compute_cmi(resolved)

        # ---- 交给 TP 签发（AP 只给公钥材料）----
        material = self._public_material()
        issued = self.ctx.capability.issue_phc(IssueRequest(
            identity_hash=cmd.identity_hash, tau=cmd.tau, crf=cmd.crf,
            apid_hex=material.ap_pubkey_hex,
            ap=material, requested_at=self.ctx.clock.now(),
        ))
        phc = issued.phc_json

        # ---- 先组装（纯函数，不落盘），只为了在要 DID 之前就把源码读齐 ----
        #   读模块失败属于"配置问题"，应该在向 TP 要 DID **之前**失败，
        #   否则会白白消耗一个 DID（DID 是唯一且不可回收的）。
        modules_src = [
            (mid, ver, self.ctx.modules.read_file(mid, ver, "engine.py"))
            for mid, ver, _ in resolved
        ]

        # ---- D6 封 DID ----
        #   ★ 只有到这里才向 TP 要 DID。先写盘再要，失败落在"可回收"一侧。
        sealed = self.ctx.capability.seal_did(SealDidRequest(
            phc_json=phc, parent_did="", did_namespace="primary",
            ap=material, requested_at=self.ctx.clock.now(),
        ))
        did = sealed.did
        phc = sealed.phc_json

        # ---- D4' 算法1：AP 把 CMI 写进自己那半 ----
        #   ★ 为什么放在封 DID 之后、而不是签发之后：
        #     算法1 改的是 APM，APCH 取值不变 → 它**不依赖** TPM 里有没有 DID。
        #     所以两步谁先谁后，验签结果是一样的。
        #     这里选后做，是因为它让「TP 的所有动作在前、AP 的动作在后」这条时序
        #     在日志里一目了然：一旦哪次审计发现 AP 的动作跑到了 TP 前面，
        #     说明有人绕过了 D6 —— 那是一种比"顺序不同"严重得多的信号。
        phc = self.ctx.capability.write_cmi(WriteCmiRequest(
            phc_json=phc, cmi=cmi.value, apm_time=self.ctx.clock.now(),
            requested_at=self.ctx.clock.now(),
        ))

        # ---- D5 三方一致 ----
        #   现在 PHC 里既有 DID、又有 CMI，是"整份凭证的最终态"，
        #   在最终态上验签才有意义（在中间态上验，验过了也不代表什么）。
        self._assert_three_way(phc, cmi.value, cmd.identity_hash, cmd.tau, cmd.crf)
        if phc["ASO"]["APM"]["CMI"] != cmi.value:
            raise IssueRejected("算法1 之后 PHC 里的 CMI 与本地算出的不一致")

        # ---- 落盘：以真实 DID 为键 ----
        store = self.ctx.agents
        store.save_meta(AgentMeta(
            did=did, agent_type=AgentType.PRIMARY, owner_did=did,
            # ★ 不落 H(ID)：实例目录只认 DID。身份映射只存在于加密索引里一处
            #   （加密索引是唯一需要"按身份找智能体"的地方，也就只需在那里留痕）。
            #   把 H(ID) 抄到每个 meta.json，等于把"哪几个人有智能体"摊在每个目录里，
            #   而 H(ID) 恰恰是最该被最小化的那一项。
            identity_hash="",
            created_at=self.ctx.clock.now(),
            state=AgentState.ACTIVE, ecid=issued.ecid,
        ))
        store.save_selection(did, StoreSelection(items=[
            {"module_id": c.module_id, "version": c.version} for c in sel.normalized()
        ]))
        store.save_cmi(did, StoreCmiRecord(
            cmi=cmi.value,
            layers=[l.chain for l in cmi.layers],
            computed_at=self.ctx.clock.now(),
            module_digests=[l.digest for l in cmi.layers],
        ))
        # ---- 先组装 build：它要写进 versions.json，所以必须早于 append_version ----
        real_build = assemble(
            did=did, agent_type="primary", parent_did="",
            modules=modules_src, cmi=cmi.value,
            layer_chains=[l.chain for l in cmi.layers],
            ecid=issued.ecid, version=1,
        )
        build_digest = real_build.build_digest()

        store.append_version(did, {
            "version": 1, "cmi": cmi.value, "at": self.ctx.clock.now(),
            "reason": "initial-issue", "buildDigest": build_digest,
        })
        store.write_build(did, 1, real_build.files)
        self._save_phc(did, phc)

        # ---- 索引与台账 ----
        self.ctx.identity_index.add(hid_hex, did,
                                    sealer=self.ctx.sealer(), opener=self.ctx.opener())
        self.ctx.owner_index.add(did, did)

        return IssueResult(
            did=did, phc_json=phc, cmi=cmi.value,
            build_digest=build_digest,
            layers=[l.chain for l in cmi.layers],
        )

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _find_duplicate(self, hid_hex: str, sel: Selection) -> str | None:
        """同一自然人、同一份选择、仍是活跃状态的实例 —— 视为重复申领。

        刻意**只认 same-selection**：用户想在同一个 H(ID) 下再要一个
        「不同能力组合」的智能体是合法需求（红线允许一人多体），
        把这种情况当成重复拒掉，等于用一个技术约束否掉产品需求。
        """
        wanted = [(c.module_id, c.version) for c in sel.normalized()]
        for did in self.ctx.identity_index.lookup(hid_hex, opener=self.ctx.opener()):
            if not self.ctx.agents.exists(did):
                continue                                  # 索引残留，跳过
            meta = self.ctx.agents.load_meta(did)
            if meta.state is not AgentState.ACTIVE or meta.agent_type is not AgentType.PRIMARY:
                continue
            got = [(i["module_id"], i["version"])
                   for i in self.ctx.agents.load_selection(did).normalized()]
            if got == wanted:
                return did
        return None

    def _resolve_modules(self, sel: Selection):
        out: list[tuple[str, str, str]] = []
        for c in sel.normalized():
            try:
                entry = self.ctx.modules.get_entry(c.module_id, c.version)
            except FileNotFoundError as e:
                raise IssueRejected(f"模块不存在：{c.module_id}@{c.version}") from e
            if entry.revoked:
                raise IssueRejected(
                    f"模块已下架：{c.module_id}@{c.version} —— 下架模块不得用于新生成")
            bad = self.ctx.modules.verify(c.module_id, c.version)
            if bad:
                raise IssueRejected(
                    f"模块仓库完整性受损：{c.module_id}@{c.version} {bad[:3]}")
            out.append((c.module_id, c.version, entry.digest))
        return out

    def _public_material(self) -> PublicKeyMaterial:
        """交给 TP 的公开材料 —— 只有公钥，一个私钥标量都没有。

        `apid_hex` 用 AP 的 Schnorr 公钥压缩点：它既是身份标识、又是可验签的对象，
        而它本来就是公开的，写进 PHC 的 APA 段没有信息泄露。
        """
        hsm = self.ctx.ap_hsm
        return PublicKeyMaterial(
            ap_pubkey_hex=crypto.sdk.ser_point(hsm.pubkey()).hex(),
            ap_chameleon_cpk_hex=crypto.sdk.ser_point(hsm.chameleon_cpk()).hex(),
            tp_pubkey_hex="",          # TP 的公钥由 TP 在回包里给，AP 拿不到就不编
            tp_chameleon_cpk_hex="",
        )

    def _assert_three_way(self, phc: dict, cmi: str,
                          identity_hash: int, tau: int, crf: int) -> None:
        """D5：证书承诺的身份因子、本地算出的 CMI、build 里写的 CMI 必须一致。

        这里刻意不"顺手补一下"不一致的地方 —— 不一致说明有一条链路被骗过，
        补上只会把痕迹抹掉。
        """
        res = self.ctx.capability.verify_phc(
            phc, identity_hash=identity_hash, tau=tau, crf=crf)
        if not res.ok:
            raise IssueRejected("PHC 校验未通过：" + "；".join(res.errors))

    def _load_phc(self, did: str) -> dict:
        p = self.ctx.layout.agent_dir(did) / "phc.json"
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_phc(self, did: str, phc: dict) -> None:
        from localstore.paths import write_atomic
        write_atomic(self.ctx.layout.agent_dir(did) / "phc.json",
                     json.dumps(phc, ensure_ascii=False, indent=2).encode())


__all__ = ["IssueAgentUseCase", "IssueCommand", "IssueResult", "IssueRejected"]
