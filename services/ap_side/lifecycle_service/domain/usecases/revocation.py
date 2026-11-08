"""承接吊销广播：把本地实例停掉。

这一段是"吊销"这件事的最后一公里。TP 侧把凭证标废了，但如果 AP 侧不停运，
那个智能体照样在跑 —— 用户看到的仍然是"它还在动"。

三条做法值得说明：

1. **不信任广播的完整性。**
   收到 `revoked` 列表后，本地还要按 parent_did 再扫一遍。
   广播可能因为超时、重试、或者 policy 侧读到了旧关系而漏掉一个子体；
   本地扫以磁盘上的事实为准，漏不掉。
   这一层冗余不是不信任对方，而是因为**漏一个就等于没吊销**。

2. **冻结而不是删除。** 见 entities 的说明。

3. **`not_local` 要如实返回。**
   广播里有一个本机没有的 DID，可能是它在别的 AP 节点上，
   也可能是有人伪造了一条吊销令。无论哪种，都必须让人看见这个数字对不上。
"""

from __future__ import annotations

from ..entities import LifecycleError, RevocationNotice, StopResult


class HandleRevocationUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, notice: RevocationNotice) -> StopResult:
        if not notice.root_did.strip():
            raise LifecycleError("吊销通知缺少 rootDid")

        # 没案由的吊销通知一律拒绝执行。
        # 这条与 policy 侧的必填校验是**两道**：广播是网络来的，不能只信上游校验过。
        if not notice.case_ref.strip():
            raise LifecycleError(
                "吊销通知缺少案由 —— 拒绝执行（广播来自网络，不能只信上游校验过）")

        now = self.ctx.clock.now()
        reason = f"凭证已吊销（案由 {notice.case_ref}）"

        stopped: list[str] = []
        already: list[str] = []
        not_local: list[str] = []

        targets = list(dict.fromkeys([notice.root_did, *notice.revoked]))

        # 1) 广播里明确点名的
        for did in targets:
            if not self.ctx.store.exists(did):
                not_local.append(did)
                continue
            meta = self.ctx.store.load_meta(did)
            if meta.state.value in ("frozen", "revoked"):
                already.append(did)
                continue
            self.ctx.store.freeze(did, reason, at=now)
            stopped.append(did)

        # 2) 本地再扫一遍后代 —— 广播漏了的，这里补上
        stopped.extend(self._sweep_descendants(notice.root_did, reason, now,
                                               skip=set(targets)))

        return StopResult(root_did=notice.root_did, stopped=stopped,
                          already=already, not_local=not_local,
                          case_ref=notice.case_ref)

    # ------------------------------------------------------------------

    def _sweep_descendants(self, root: str, reason: str, now: str,
                           *, skip: set[str]) -> list[str]:
        """按本机 meta.json 的 parent_did 逐层扫。

        ★ 只扫本机：AP 无权也不该去遍历别的节点的资产。
          跨节点的传播靠广播本身，本机这层只保证"我这里不漏"。
        """
        all_agents = self.ctx.store.iter_all()
        by_parent: dict[str, list] = {}
        for m in all_agents:
            if m.parent_did:
                by_parent.setdefault(m.parent_did, []).append(m)

        out: list[str] = []
        frontier = [root]
        seen: set[str] = {root}
        while frontier:
            cur = frontier.pop()
            for m in by_parent.get(cur, []):
                if m.did in seen:
                    continue
                seen.add(m.did)
                if m.did in skip:
                    frontier.append(m.did)
                    continue
                if m.state.value in ("frozen", "revoked"):
                    frontier.append(m.did)
                    continue
                self.ctx.store.freeze(m.did, reason, at=now)
                out.append(m.did)
                frontier.append(m.did)
        return out


__all__ = ["HandleRevocationUseCase"]
