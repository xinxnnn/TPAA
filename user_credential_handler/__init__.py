"""服务端用户凭证处理器：开发测试用的密钥与协议状态持有者。

不代表用户独立控钥；生产环境需要单独的用户持有端与安全密钥存储。
"""

from .handler import UserCredentialHandler, CredentialHandlerError

__all__ = ["UserCredentialHandler", "CredentialHandlerError"]
