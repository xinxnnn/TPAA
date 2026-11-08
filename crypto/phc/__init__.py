"""PHC 人格凭证：结构与签发 / 更新引擎。

    schema.PHC        四段结构（ASO / TPA / APA / PROOF）
    engine.issue_phc      G3    TP 初始化签发
    engine.update_by_ap   算法1  AP 驱动更新（★ 改内容而签名不变）
    engine.update_by_tp   算法2  TP 驱动更新（生成 DID）
    engine.verify_phc     完整校验，返回错误列表
"""

from . import engine, schema
from .engine import issue_phc, update_by_ap, update_by_tp, verify_phc
from .schema import PHC

__all__ = ["schema", "engine", "PHC", "issue_phc", "update_by_ap", "update_by_tp", "verify_phc"]
