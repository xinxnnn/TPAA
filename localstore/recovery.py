"""recovery.py —— 「读取即校验」与级联的落地实现（红线 15 + RE2）。

RE2 原文那一步是三个动作：
    1. 用 H(ID) 从本地数据库检索模块代码
    2. 对比凭证中提取的 CMI 与本地存储的是否一致
    3. 一致才重建

本模块负责第 2 步的**判据**与不一致时的**处置**。处置只有一种：冻结 + 告警，
不做「自动修复」—— 校验不通过说明有人动过磁盘，此时任何自动修正都是在帮攻击者擦痕迹。
"""

from __future__ import annotations

from .agents import AgentStore, AgentState
from .paths import Layout


class GuardViolation(RuntimeError):
    """读到的内容与凭证里的承诺不符 —— 磁盘内容已不可信。

    两种成因走同一条处置（冻结 + 告警），但**必须说清是哪一种**：
        CMI 不一致      本地重算的 CMI ≠ 凭证承诺的 CMI（selection 或模块被换过）
        仓库完整性受损  模块文件与 manifest 摘要不符（模块仓库被动过）
    两者的共同点是"这个实例已经不可交付"，区别在排查方向完全不同。
    所以这里留一个 `detail`，让告警里带上具体是哪一段对不上。
    """

    def __init__(self, did: str, expected: str, actual: str,
                 *, detail: str = "") -> None:
        core = detail or (f"CMI 不一致：PHC 承诺 {expected[:16]}…，"
                          f"本地 {actual[:16]}…")
        super().__init__(f"{did} 已冻结（{core}）")
        self.did = did
        self.expected = expected
        self.actual = actual
        self.detail = core


def assert_cmi_matches(
    store: AgentStore,
    did: str,
    expected_cmi: str,
    *,
    at: str,
) -> None:
    """把「凭证里的 CMI」与「本地算出的 CMI」对上；对不上就冻结并抛出。

    冻结发生在抛出之前 —— 先把现场保住，再让调用方看到错误。
    """
    rec = store.load_cmi(did)
    if rec.cmi != expected_cmi:
        store.freeze(did, f"CMI 校验失败：凭证说 {expected_cmi[:16]}…", at=at)
        raise GuardViolation(did, expected_cmi, rec.cmi)


def cascade_freeze(
    store: AgentStore,
    root_did: str,
    *,
    at: str,
    reason: str,
) -> list[str]:
    """按 parent_did 逐层扫出全部后代并冻结。

    为什么是「扫」而不是「存」：
        若在父体里维护 children 列表，任何一次写入失败都会让级联漏掉一个子体 ——
        漏掉的子体继续活着，就是吊销失效。扫 meta.json 是以「事实」为准，
        写入失败最多让某个子体晚一轮被冻，不会被悄悄遗忘。

    为什么是「冻结」而不是「删除」：
        吊销的价值一半在取证。删掉之后，追溯链上的那一环就永远说不清了。
    """
    frozen: list[str] = []
    frontier = [root_did]
    seen: set[str] = {root_did}
    all_agents = store.iter_all()
    while frontier:
        parent = frontier.pop()
        for meta in all_agents:
            if meta.parent_did == parent and meta.did not in seen:
                seen.add(meta.did)
                if meta.state is not AgentState.FROZEN:
                    store.freeze(meta.did, reason, at=at)
                    frozen.append(meta.did)
                frontier.append(meta.did)
    return frozen


def place_in_recycle(layout: Layout, store: AgentStore, did: str, *, at: str) -> str:
    """软删：移入 recycle/，保留恢复窗口。索引同步摘除由调用方负责（它才持有密钥）。"""
    import shutil

    src = layout.agent_dir(did)
    dst = layout.recycled(did)
    if not src.exists():
        raise FileNotFoundError(f"实例不存在：{did}")
    store.revoke(did, at=at, reason="moved-to-recycle")
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return str(dst)


__all__ = ["GuardViolation", "assert_cmi_matches", "cascade_freeze", "place_in_recycle"]
