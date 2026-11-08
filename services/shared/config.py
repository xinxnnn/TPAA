"""服务域标签与默认端口（步骤 7 骨架）。

域标签用于网络策略（Namespace / NetworkPolicy）与审计归属，
见 ARCHITECTURE.md §十（部署与网络拓扑）。
"""

from __future__ import annotations

# 责任方域：决定团队归属、部署域与网络策略（不放松运行时约束）
SERVICE_DOMAINS = {
    "user-side", "tp-side", "ap-side", "cross-domain", "ipfs-side",
}

# 各服务默认监听端口（骨架约定，实际部署由编排决定）
DEFAULT_PORTS: dict[str, int] = {
    "portal-api": 8100,
    "order-service": 8101,
    "agent-vault": 8102,
    "identity-service": 8200,
    "review-service": 8201,
    "phc-service": 8202,
    "did-service": 8203,
    "supervision-service": 8204,
    "agent-service": 8300,
    "subagent-service": 8301,
    "lifecycle-service": 8302,
    "gateway": 8000,
    "policy-service": 8401,
    "audit-service": 8402,
    "coordination": 8403,
}

__all__ = ["SERVICE_DOMAINS", "DEFAULT_PORTS"]
