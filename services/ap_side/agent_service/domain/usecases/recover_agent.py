"""用例 3：找回（ARCHITECTURE §9.4 的 RE 步骤）。

协议原文那一步是四句话，本用例逐句对应：

    1. 用 H(ID) 查 localstore/index/by-identity.enc          → `locate`
    2. 取 selection.json（所选模块与版本）                    → `load_selection`
    3. 从 modules/ 取对应版本代码                             → `_gather_modules`
    4. 重算 CMI，与 cmi.json 比对                             → `_recompute_and_check`

一致 → 重建 build → 交付；不一致 → 告警并冻结。**没有第三种处置。**

为什么"重建"是安全的：
    build 是 selection + modules 的确定性函数（见 services/build.py），
    所以「重建出来的 build」和「当初那份 build」在本该相同的地方必须相同。
    这里额外比一次 buildDigest：它若变了，说明是 selection 或模块被换过，
    而不是磁盘上次生成了个不一样的东西 —— 这两种情况的处置不一样，
    所以要在告警里说清楚是哪一种。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from localstore import AgentState, GuardViolation, assert_cmi_matches

from ..entities import Agent, State
from ..services.build import assemble
from ..services.cmi import compute_cmi
from ..services.context import AgentServiceContext
from ..services.ttl import sweep_expired


class RecoverRejected(RuntimeError):
    pass


@dataclass
class RecoverResult:
    did: str
    rebuilt: bool
    cmi: str
    build_digest: str
    build_digest_changed: bool = False
    note: str = ""
    candidates: list[str] = field(default_factory=list)


class RecoverAgentUseCase:
    def __init__(self, ctx: AgentServiceContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------
    # 列候选：RE 之前先让用户看到"你名下有哪些智能体"
    # ------------------------------------------------------------------
    def locate(self, identity_hash: int) -> list[dict]:
        """用 H(ID) 列出此人名下全部实例（含子体），带上状态与 TTL 判定。

        ★ 只列，不改状态：过期清扫是后台动作（sweep），
          在一次"查看"里顺手冻几个实例，会让用户以为系统在乱动东西。
        """
        hid = f"{identity_hash:064x}"
        out: list[dict] = []
        for did in self.ctx.identity_index.lookup(hid, opener=self.ctx.opener()):
            if not self.ctx.agents.exists(did):
                out.append({"did": did, "state": "missing", "note": "索引残留：本地无此实例"})
                continue
            m = self.ctx.agents.load_meta(did)
            out.append({
                "did": did,
                "agentType": m.agent_type.value,
                "state": m.state.value,
                "parentDid": m.parent_did,
                "expiresAt": m.expires_at,
                "expired": self.ctx.clock.now() > m.expires_at if m.expires_at else False,
            })
        return out

    # ------------------------------------------------------------------
    # 真正的找回
    # ------------------------------------------------------------------
    def execute(self, *, identity_hash: int, did: str) -> RecoverResult:
        hid = f"{identity_hash:064x}"

        # ---- 0) 先确认「这个 DID 确实属于这个 H(ID)」----
        #   少了这一步，任何人拿一个 DID 就能去重建别人的智能体。
        owned = self.ctx.identity_index.lookup(hid, opener=self.ctx.opener())
        if did not in owned:
            raise RecoverRejected(
                f"{did} 不在该身份名下（找回必须由本人发起，且只能找回自己的实例）")

        # ---- 1) 状态闸门 ----
        meta = self.ctx.agents.load_meta(did)
        agent = Agent(
            did=meta.did, owner_did=meta.owner_did,
            identity_hash=meta.identity_hash, agent_type=meta.agent_type.value,
            parent_did=meta.parent_did, expires_at=meta.expires_at,
            state=State(meta.state.value), frozen_reason=meta.frozen_reason,
        )
        agent.ensure_deliverable()          # 冻结/吊销 → 直接拒，且不重建

        # 子体还要看父体是否还活着 —— 父体没了，子体不该继续被交付
        if meta.parent_did:
            pmeta = self.ctx.agents.load_meta(meta.parent_did)
            if pmeta.state is not AgentState.ACTIVE:
                raise RecoverRejected(
                    f"父体 {meta.parent_did} 当前为 {pmeta.state.value}，子体不得交付")
            if self.ctx.clock.now() > meta.expires_at:
                raise RecoverRejected(
                    f"子体已过期（{meta.expires_at}）—— 过期实例不提供找回，只能重新派生")

        # ---- 2) PHC 是否还在、还对不对 ----
        phc = self._load_phc(did)
        if not phc:
            raise RecoverRejected(
                "本地无 PHC —— 需走 T1：由 TP 用 RF 还原原始 PHC 后再找回")

        # ---- 3) RE：selection → modules → 重算 CMI ----
        sel = self.ctx.agents.load_selection(did)
        items = sel.normalized()
        resolved = []
        for item in items:
            mid, ver = item["module_id"], item["version"]
            try:
                entry = self.ctx.modules.get_entry(mid, ver)
            except FileNotFoundError as e:
                # 模块被删了 —— 这不是"不一致"，是"缺件"，要说清楚
                raise RecoverRejected(
                    f"模块缺失：{mid}@{ver} —— build 无法重建（需 AP 侧重新上架该版本）") from e

            # ★ 先验模块仓库：磁盘上的模块内容必须还和 manifest 摘要一致。
            #   为什么这一步也要**冻结**、而不是直接 400 退回：
            #     模块被改 → 重算出的 CMI 必然与凭证不符 → 这个实例已经不可信了。
            #     若只是"这次请求失败"而不冻，实例仍处于 active：用户下次点一次
            #     重建、或者 runtime 直接拉起它，都会拿着被换过的代码跑起来 ——
            #     平台明明已经知道它坏了，却让它继续活下去。
            #   所以这里的处置与 CMI 不一致完全同级：先冻结，再报错。
            bad = self.ctx.modules.verify(mid, ver)
            if bad:
                reason = (f"模块仓库完整性受损：{mid}@{ver}"
                          f"（{bad[0]}，共 {len(bad)} 处）")
                self.ctx.agents.freeze(did, reason, at=self.ctx.clock.now())
                rec = self.ctx.agents.load_cmi(did)
                raise GuardViolation(did, rec.cmi, rec.cmi, detail=reason)

            resolved.append((mid, ver, entry.digest))

        recomputed = compute_cmi(resolved)

        # ---- 4) 与 cmi.json 比对：不一致即冻结 + 抛错 ----
        #   直接让 GuardViolation 冒上去，不在这里再包一次 ——
        #   包一层只会把 detail 丢掉，最终告警里又变成一句没信息量的"CMI 不一致"。
        assert_cmi_matches(self.ctx.agents, did, recomputed.value,
                           at=self.ctx.clock.now())

        # ---- 5) 重建 build 并核对 buildDigest ----
        modules_src = [
            (mid, ver, self.ctx.modules.read_file(mid, ver, "engine.py"))
            for mid, ver, _ in resolved
        ]
        version = self.ctx.agents.current_version(did)
        build = assemble(
            did=did, agent_type=meta.agent_type.value,
            parent_did=meta.parent_did, modules=modules_src,
            cmi=recomputed.value, layer_chains=[l.chain for l in recomputed.layers],
            ecid=meta.ecid, version=version,
        )

        old_digest = ""
        for v in self.ctx.agents.load_versions(did):
            if int(v.get("version", -1)) == version:
                old_digest = str(v.get("buildDigest", ""))

        changed = bool(old_digest) and old_digest != build.build_digest()
        if changed:
            # build 内容变了但 CMI 没变 —— 说明模块内容的"呈现"变了（例如打包规则被改），
            # 这不是协议层面的失败，但必须记下来，不静默覆盖。
            self.ctx.agents.append_version(did, {
                "version": version, "at": self.ctx.clock.now(),
                "reason": "recover-build-digest-changed",
                "buildDigest": build.build_digest(), "previousDigest": old_digest,
            })

        self.ctx.agents.write_build(did, version, build.files)
        return RecoverResult(
            did=did, rebuilt=True, cmi=recomputed.value,
            build_digest=build.build_digest(), build_digest_changed=changed,
            candidates=[m.did for m in self.ctx.agents.iter_all()],
            note="buildDigest 与上次不同，已在 versions.json 留痕" if changed else "",
        )

    # ------------------------------------------------------------------
    def sweep(self) -> list[str]:
        """到期清扫：把过期子体置为冻结（不删，保留取证）。"""
        return sweep_expired(self.ctx)

    def _load_phc(self, did: str) -> dict:
        p = self.ctx.layout.agent_dir(did) / "phc.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


__all__ = ["RecoverAgentUseCase", "RecoverResult", "RecoverRejected"]
