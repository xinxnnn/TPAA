"""Event-to-macro construction for the explicit approved experiment only."""
from dataclasses import dataclass, field

from . import chameleon as ch
from . import executable_profile as profile
from .experiment_profiles import keccak_typed_duplicate_last
from .merkle import MerkleTree
from .memory import MacroPoint


def _sequence(events):
    sequence = tuple(tuple(event) for event in events)
    if not sequence or any(len(event) != 5 or any(type(v) is not str or not v for v in event)
                           for event in sequence):
        raise ValueError('Nonempty ordered five-component synthetic events required')
    return sequence


@dataclass(frozen=True)
class Macro:
    identifier: str
    point: MacroPoint
    digests: tuple[int, ...] = field(repr=False)
    root: bytes
    ch_root: bytes
    randomness: int = field(repr=False)


def construct(identifier: str, time_id: str, pa_did: str, events, public_key: bytes,
              *, randomness: int) -> Macro:
    if any(type(v) is not str or not v for v in (identifier, time_id, pa_did)):
        raise ValueError('Explicit macro ID, time and PA DID required')
    if type(randomness) is not int or not 0 <= randomness < profile.ORDER:
        raise ValueError('Expected canonical initial randomness')
    digests = tuple(profile.h2(event) for event in _sequence(events))
    root = MerkleTree(tuple(profile.scalar_bytes(d) for d in digests),
                      parameters=keccak_typed_duplicate_last()).root
    ch_root = ch.generate(public_key, root, randomness, h0=profile.h0)
    x = profile.h1(time_id, pa_did, identifier)
    y = profile.h1(profile.scalar_bytes(x), ch_root)
    return Macro(identifier, MacroPoint(x, y), digests, root, ch_root, randomness)


def append(macro: Macro, events, secret_key: int) -> Macro:
    public_key = ch.backend.multiply(ch.backend.generator(1), secret_key, 1)
    expected_root = MerkleTree(tuple(profile.scalar_bytes(d) for d in macro.digests),
                               parameters=keccak_typed_duplicate_last()).root
    if expected_root != macro.root or ch.generate(public_key, macro.root, macro.randomness,
                                                  h0=profile.h0) != macro.ch_root:
        raise ValueError('Macro opening or PA key mismatch')
    if profile.h1(profile.scalar_bytes(macro.point.x), macro.ch_root) != macro.point.y:
        raise ValueError('Macro ordinate mismatch')
    digests = macro.digests + tuple(profile.h2(event) for event in _sequence(events))
    root = MerkleTree(tuple(profile.scalar_bytes(d) for d in digests),
                      parameters=keccak_typed_duplicate_last()).root
    rho = ch.adapt(secret_key, macro.root, macro.randomness, root, h0=profile.h0)
    if not ch.verify_collision(public_key, macro.root, macro.randomness, root, rho, h0=profile.h0):
        raise ValueError('APPEND adaptation failed')
    return Macro(macro.identifier, macro.point, digests, root, macro.ch_root, rho)
