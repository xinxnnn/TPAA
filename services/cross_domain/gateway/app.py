"""gateway —— cross-domain 方服务骨架（步骤 7）。

分层见 ARCHITECTURE.md §7.2：api / domain / infra / crypto_client / events。
加解密一律经 crypto.sdk（见 crypto_client/），不得直连 crypto 内部实现（红线 2）。
"""

from services.shared.app_base import build_app

app = build_app(title="gateway", domain="cross-domain")

__all__ = ["app"]
