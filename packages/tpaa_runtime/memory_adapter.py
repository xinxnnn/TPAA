"""Framework-independent boundary for future AG2 integration.

No crypto internals or secrets cross this boundary. Implementations live in
the trusted service/SDK; adapters cannot choose or silently revise protocol rules.
"""
from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class MemoryEvent:
    time: str
    action: str
    object: str
    subject: str
    method: str


@dataclass(frozen=True)
class UpdateReceipt:
    status: str
    commitment: bytes | None
    public_trace_id: str | None
    unresolved_rules: tuple[str, ...] = ()


class EventSource(Protocol):
    def events(self) -> Iterable[MemoryEvent]: ...


class GraphAdapter(Protocol):
    def neighbors(self, event: MemoryEvent) -> tuple[str, ...]: ...


class MemoryGateway(Protocol):
    def submit(self, events: tuple[MemoryEvent, ...], *, interaction_type: str) -> UpdateReceipt:
        """Calls trusted module; does not accept sUser, skPA, theta or raw coefficients."""
        ...


class MemoryAuthenticator(Protocol):
    def bootstrap(self, service_did: str) -> UpdateReceipt: ...
    def continuous(self, service_did: str) -> UpdateReceipt: ...
