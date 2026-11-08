"""AP 侧对协查的应答：给出归属证明。

协查要的是"公开材料"，所以应答里只有三样东西：

    parentDid   本机 meta.json 里记的父指针
    phcJson     本机 phc.json 的**规范化字符串**（跨域通道只放标量）
    phcDigest   它的 sha256，便于 TP 侧比对"你给的是不是同一份"

★ 为什么不返回 H(ID) 或随机因子：
  我们这套实现里，H(ID) 的还原走的是 TP 自己的 CSCID（路径 A），
  AP 完全不参与 —— 它手里也没有 H(ID) 明文（红线 13）。
  随机因子 AF_r 在 PHC 里本来就是公开字段，跟着 phcJson 一起过去就够了。
  多给一样东西，就多一条"AP 能自证身份"的错觉。

★ 不给不存在的东西：
  本机没有这个实例，就明说"不在本机"，而不是给一份猜的。
  追溯链上最怕的就是"某一段是猜的"，因为下游会把它当成事实继续用。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


class AssistError(RuntimeError):
    """协查应答被拒。"""


@dataclass(frozen=True)
class AssistResult:
    kind: str
    answer: dict


class AnswerAssistUseCase:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def execute(self, *, kind: str, payload: dict) -> AssistResult:
        did = str(payload.get("did") or "").strip()
        if not did:
            raise AssistError("协查载荷缺少 did")
        if kind != "lineage_proof":
            raise AssistError(
                f"不支持的协查类别 {kind!r} —— AP 侧只应答归属证明；"
                "别的类别一律拒绝，而不是给一个笼统的空答案")

        if not self.ctx.store.exists(did):
            raise AssistError(f"{did} 不在本机 —— 该实例可能在其他 AP 节点")

        meta = self.ctx.store.load_meta(did)
        phc_path = self.ctx.store.layout.agent_dir(did) / "phc.json"
        if not phc_path.exists():
            raise AssistError(f"{did} 本机缺少 phc.json —— 无法提供归属证明")

        phc = json.loads(phc_path.read_text(encoding="utf-8"))
        phc_json_str = json.dumps(phc, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":"))
        answer = {
            "did": did,
            "parentDid": meta.parent_did or "",
            "agentType": meta.agent_type.value if hasattr(meta.agent_type, "value")
                         else str(meta.agent_type),
            "state": meta.state.value if hasattr(meta.state, "value") else str(meta.state),
            # ★ 通道只收标量：PHC 以规范化 JSON 字符串过去，回来再解析
            "phcJson": phc_json_str,
            "phcDigest": hashlib.sha256(phc_json_str.encode()).hexdigest(),
        }
        return AssistResult(kind=kind, answer=answer)


__all__ = ["AnswerAssistUseCase", "AssistResult", "AssistError"]
