"""localstore —— 已生成智能体的存放地（ARCHITECTURE §7.1 / 红线 13–15）。

协议依据：RE2 步骤「AP 利用身份哈希值从本地数据库检索存储的模块代码，
并对比凭证中提取的 CMI 与本地存储的是否一致」。
这个「本地数据库」就是本包 —— 找回能力能否成立，取决于这里存得对不对、查得到查不到。

三条边界（本包在实现层守住的）：

1. **业务层不碰密码学内部**：哈希链一律经 crypto.sdk（红线 2）。本包因此属于
   `_BUSINESS_ROOTS`，`crypto.guard` 对它照常扫描。
2. **不存身份明文**：实例目录里只有 DID / ID 哈希 / CMI；H(ID) → agent_id 的映射
   单独放在 `index/by-identity.enc`，用调用方给的密钥加封（红线 13）。
3. **读取即校验**：任何读实例的动作都要过 CMI 比对，不一致立刻冻结（红线 15）。

本模块只做导出，实现按职责拆在 paths / modules / agents / index / recovery 里。
"""

from __future__ import annotations

# ★ 唯一的密码学出口：本包只经 crypto.sdk（红线 2）。
# 用包级 import + 属性访问 —— from-import 会把引擎函数捕进本包命名空间，
# 调用处就看不出密码边界在哪，guard R2 也不放行。
import crypto.sdk

protect_cid = crypto.sdk.protect_cid
recover_cid = crypto.sdk.recover_cid

from .paths import Layout, StoreLayoutError, encode_agent_id
from .modules import ModuleRepo, ModuleEntry
from .agents import AgentStore, AgentMeta, AgentState, AgentType, Selection, CmiRecord
from . import index
from .index import IdentityIndex, OwnerIndex, IndexCorrupted
from .recovery import (
    GuardViolation,
    assert_cmi_matches,
    cascade_freeze,
    place_in_recycle,
)

__all__ = [
    "protect_cid",
    "recover_cid",
    "Layout",
    "StoreLayoutError",
    "encode_agent_id",
    "ModuleRepo",
    "ModuleEntry",
    "AgentStore",
    "AgentMeta",
    "AgentState",
    "AgentType",
    "Selection",
    "CmiRecord",
    "IdentityIndex",
    "OwnerIndex",
    "IndexCorrupted",
    "GuardViolation",
    "assert_cmi_matches",
    "cascade_freeze",
    "place_in_recycle",
]
