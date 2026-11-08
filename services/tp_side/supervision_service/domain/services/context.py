"""supervision-service 的共享上下文与启动自检。

这里持有监管密钥 —— 全系统唯一能还原 H(ID) 的东西。

★ 所以自检里第一条就是：**密钥必须还在**。
  一把被序列化降级过的密钥（只剩公钥）会让服务"看起来正常"，
  然后在第一次真正需要揭露身份时抛 PermissionError。
  那种失败发生在最不该失败的时刻，所以要在启动时就查出来。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """启动自检未通过。"""


@dataclass
class SupervisionContext:
    cases: object                   # CaseStore
    directory: object               # DirectoryPort
    channel: object                 # ChannelPort
    storage: object                 # StoragePort
    audit: object                   # AuditSink
    key: object                     # crypto.sdk.SupervisionKey（含解密能力）
    clock: object                   # Clock
    # TP 的变色龙公钥句柄（**公开材料**）—— 用来复算 AF，验证揭露结果
    tp_ch: object | None = None
    policy: dict = field(default_factory=dict)

    def preflight(self) -> list[str]:
        errors: list[str] = []

        # 1) 监管密钥必须在，且**未降级**
        if self.key is None:
            errors.append("缺少监管密钥：无法还原身份，追溯链在最后一公里断掉")
        else:
            present = getattr(self.key, "private_key_present", None)
            if callable(present) and not present():
                errors.append(
                    "监管密钥已被序列化降级（只剩公钥）—— "
                    "服务能起来但永远解不开 CSCID；请重新注入原始密钥")

        # 2) 四个端口
        for name in ("directory", "channel", "storage", "audit", "clock"):
            if getattr(self, name) is None:
                errors.append(f"缺少端口：{name}")

        # 3) 案件库
        if self.cases is not None:
            try:
                self.cases.self_check()
            except Exception as exc:                 # noqa: BLE001
                errors.append(f"案件库不可用：{exc}")

        # 4) 审计必须在 —— 立案这件事本身的记录，比任何一条协查都重要
        if self.audit is not None:
            probe = getattr(self.audit, "probe", None)
            if callable(probe):
                ok, why = probe()
                if not ok:
                    errors.append(f"审计归档不可用：{why}")

        # 5) TP 公钥句柄缺失不算错误，但要挂出来：
        #    没有它，揭露结果无法用 AF 复核，每一份揭露都会标 verified=False。
        #    这是"降级"不是"故障"，但必须一直看得见。
        self._warnings: list[str] = []
        if self.tp_ch is None:
            self._warnings.append(
                "未注入 TP 公钥句柄：揭露结果无法用 AF 复核（verified 恒为 False）")

        return errors

    def warnings(self) -> list[str]:
        return list(getattr(self, "_warnings", []))

    def ensure_healthy(self) -> None:
        errs = self.preflight()
        if errs:
            raise ConfigError(
                "supervision-service 启动自检未通过：\n  - " + "\n  - ".join(errs))


__all__ = ["SupervisionContext", "ConfigError"]
