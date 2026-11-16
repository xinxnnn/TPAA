"""User-approved graph interpretation for synthetic experiments only."""
from dataclasses import dataclass

from .memory_adapter import MemoryEvent

TYPES = ('time', 'action', 'object', 'subject', 'method')


def typed_nodes(event: MemoryEvent) -> frozenset[tuple[str, str]]:
    values = tuple(getattr(event, name) for name in TYPES)
    if any(type(value) is not str or not value for value in values):
        raise ValueError('Synthetic event requires five nonempty typed node IDs')
    return frozenset(zip(TYPES, values))


@dataclass(frozen=True)
class SyntheticMacro:
    identifier: str
    events: tuple[MemoryEvent, ...]


@dataclass(frozen=True)
class Decision:
    operation: str
    macro_id: str | None
    scores: tuple[tuple[str, int], ...]


def adjudicate(events: tuple[MemoryEvent, ...], macros: tuple[SyntheticMacro, ...],
               *, interaction_type: str) -> Decision:
    if interaction_type not in ('internal', 'external'):
        raise ValueError('Unknown interaction type')
    if not events:
        raise ValueError('Nonempty event subgraph required')
    identifiers = [macro.identifier for macro in macros]
    if any(type(i) is not str or not i for i in identifiers) or len(set(identifiers)) != len(identifiers):
        raise ValueError('Distinct nonempty macro IDs required')
    new_nodes = frozenset().union(*(typed_nodes(event) for event in events))
    scores = []
    for macro in macros:
        old_nodes = frozenset().union(*(typed_nodes(event) for event in macro.events))
        scores.append((macro.identifier, len(new_nodes & old_nodes)))
    scores.sort(key=lambda pair: pair[0].encode('utf-8'))
    if interaction_type == 'external' or not scores or max(score for _, score in scores) == 0:
        return Decision('CREATE', None, tuple(scores))
    maximum = max(score for _, score in scores)
    chosen = next(identifier for identifier, score in scores if score == maximum)
    return Decision('APPEND', chosen, tuple(scores))
