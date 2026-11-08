"""index/ —— 两条索引。它们是 localstore 里唯一「跨实例」的结构。

| 文件 | 内容 | 为什么必须单独对待 |
|---|---|---|
| `by-identity.enc` | H(ID) → agent_id 列表 | **全目录唯一**含身份映射关系的文件。H(ID) 虽是哈希，但配合身份证库可被反查，因此整文件以 AEAD 加封 |
| `by-owner-did.json` | owner_did → agent_id 列表 | 键与值都是 DID，不含身份信息，可明文 |

为什么不把 H(ID) 放进 meta.json：
    那样每个实例目录都成了「身份映射」，要保护的面就从 1 个文件变成 N 个。
    RE2 找回只需要「给定 H(ID) 能列出实例」，一个索引足矣。

加封用什么：**仅经 crypto.sdk**（红线 2）。这里复用信封的 `protect_cid` ——
它就是「把一个字符串用派生密钥封成不可读文本」，与本处需求同构，
且已在步骤 4 被对抗用例验证过。密钥由调用方（agent-service）注入，索引自己不产密钥。

★ `crypto.sdk` 是上层唯一合法入口，但本项目的上层**import 惯例是直写**
  （`from crypto.sdk import ...`），而 guard R2 认的是 `crypto.sdk.*` 前缀。
  因此本包在 `localstore/__init__.py` 里把 sdk 的两个函数**重导出**，
  其余子模块一律 `from . import protect_cid, recover_cid` —— 写在文件里指不回任何
  内部实现，卡口扫得到、读者也一眼看见「这里只经 sdk」。
"""

from __future__ import annotations

import json
from typing import Callable

from . import protect_cid, recover_cid

from .paths import Layout, write_atomic

# 索引加封/解封的两个函数签名，注入式 —— 索引层不自己跑去 HSM 取密钥
Sealer = Callable[[str], str]
Opener = Callable[[str], str]


class IndexCorrupted(RuntimeError):
    """索引解封失败或结构非法 —— 拿错密钥，或文件被替换。"""


class IdentityIndex:
    """H(ID) → agent_id（= DID）。读取需要密钥。"""

    def __init__(self, layout: Layout) -> None:
        self.layout = layout
        self.path = layout.identity_index

    # ---- 密钥绑定 ----
    @staticmethod
    def sealer(key: bytes) -> Sealer:
        return lambda plain: protect_cid(plain, key)

    @staticmethod
    def opener(key: bytes) -> Opener:
        return lambda sealed: _recover_or_raise(sealed, key)

    def _load(self, opener: Opener) -> dict[str, list[str]]:
        if not self.path.exists():
            return {}
        sealed = self.path.read_text(encoding="utf-8")
        raw = opener(sealed)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:      # pragma: no cover - 概率极低
            raise IndexCorrupted(f"索引明文不是合法 JSON：{e}") from e
        if not isinstance(data, dict):
            raise IndexCorrupted("索引结构非法：顶层应为对象")
        return {str(k): [str(x) for x in v] for k, v in data.items()}

    def _save(self, data: dict[str, list[str]], sealer: Sealer) -> None:
        plain = json.dumps(data, ensure_ascii=False, sort_keys=True)
        write_atomic(self.path, sealer(plain).encode())

    # ---- 读写 ----
    def add(self, identity_hash: str, did: str, *, opener: Opener, sealer: Sealer) -> None:
        data = self._load(opener)
        bucket = data.setdefault(identity_hash, [])
        if did not in bucket:
            bucket.append(did)
            bucket.sort()
        self._save(data, sealer)

    def remove(self, identity_hash: str, did: str, *, opener: Opener, sealer: Sealer) -> None:
        data = self._load(opener)
        bucket = [x for x in data.get(identity_hash, []) if x != did]
        if bucket:
            data[identity_hash] = bucket
        else:
            data.pop(identity_hash, None)
        self._save(data, sealer)

    def lookup(self, identity_hash: str, *, opener: Opener) -> list[str]:
        """RE2 的第一步：用 H(ID) 列出该自然人名下全部智能体（含子体）。"""
        return list(self._load(opener).get(identity_hash, []))

    def find_by_did(self, did: str, *, opener: Opener) -> str:
        """反查：已知 DID，求它属于哪个 H(ID)。找不到返回空串。

        ★ 为什么需要它：派生子体时必须知道"H(ID) 是多少"（子体 PHC 的身份因子
          与索引登记都要用），而 meta.json **刻意不存 H(ID)**（不存，才能让
          "身份映射全库只有一处"这句话在数据层面成立，而不是靠自觉）。
          于是只剩两个来源：要么由调用方传来（危险 —— 等于允许替别人点头），
          要么从索引反查（这里）。选后者：H(ID) 始终来自服务端自己登记过的事实。

        代价是一次全索引扫描。按单自然人的实例数量（个位数）算，这个代价可忽略；
        如果哪天一个 H(ID 下有上千子体，再考虑维护 did→H(ID) 的辅索引 —— 那时
        它同样必须是加密的，否则只是把问题挪了个地方。
        """
        for hid, dids in self._load(opener).items():
            if did in dids:
                return hid
        return ""

    def count(self, *, opener: Opener) -> int:
        return sum(len(v) for v in self._load(opener).values())


def _recover_or_raise(sealed: str, key: bytes) -> str:
    raw = recover_cid(sealed, key)
    if raw is None:
        raise IndexCorrupted("身份索引解封失败：密钥不正确，或文件已被替换")
    return raw


class OwnerIndex:
    """owner_did → agent_id。键值皆为 DID，明文即可；用于台账与级联扫描的快速定位。"""

    def __init__(self, layout: Layout) -> None:
        self.layout = layout
        self.path = layout.owner_index

    def _load(self) -> dict[str, list[str]]:
        if not self.path.exists():
            return {}
        return {str(k): [str(x) for x in v]
                for k, v in json.loads(self.path.read_text(encoding="utf-8")).items()}

    def _save(self, data: dict[str, list[str]]) -> None:
        write_atomic(self.path,
                     json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode())

    def add(self, owner_did: str, did: str) -> None:
        data = self._load()
        bucket = data.setdefault(owner_did, [])
        if did not in bucket:
            bucket.append(did)
            bucket.sort()
        self._save(data)

    def remove(self, owner_did: str, did: str) -> None:
        data = self._load()
        bucket = [x for x in data.get(owner_did, []) if x != did]
        if bucket:
            data[owner_did] = bucket
        else:
            data.pop(owner_did, None)
        self._save(data)

    def lookup(self, owner_did: str) -> list[str]:
        return list(self._load().get(owner_did, []))

    def all_owners(self) -> list[str]:
        return sorted(self._load())


__all__ = ["IdentityIndex", "OwnerIndex", "IndexCorrupted"]
