"""PDF Phase 1 polynomial state transitions, without implicit graph/hash rules.

Inputs are already constructed macro-node field points. These functions do not
choose H1/H2, derive theta, authorize a caller, or resolve Adjudicate ties.
States and coefficients belong inside the simulated trusted boundary.
"""
from dataclasses import dataclass, field

from . import pairing_backend as b
from .polynomial import Polynomial, interpolate, vanishing
from .srs import SRS


def scalar(value):
    if type(value) is not int or not 0 <= value < b.ORDER:
        raise ValueError('Expected canonical Fq scalar')
    return value


@dataclass(frozen=True)
class MacroPoint:
    x: int
    y: int

    def __post_init__(self):
        scalar(self.x)
        scalar(self.y)


@dataclass(frozen=True)
class MemoryState:
    points: tuple[MacroPoint, ...] = field(repr=False)
    initial_polynomial: Polynomial = field(repr=False)
    polynomial: Polynomial = field(repr=False)
    commitment: bytes
    anchor: bytes
    srs_id: str


def _points(points):
    points = tuple(points)
    if not points or any(not isinstance(p, MacroPoint) for p in points):
        raise ValueError('Macro-node field points required')
    if len({p.x for p in points}) != len(points):
        raise ValueError('Duplicate macro-node coordinate')
    return points


def validate(srs: SRS, state: MemoryState) -> None:
    if state.srs_id != srs.identifier:
        raise ValueError('Memory state SRS mismatch')
    points = _points(state.points)
    if points[0].x != 0 or len(points) > srs.maximum_degree:
        raise ValueError('Invalid genesis point or macro-node limit')
    for polynomial in (state.initial_polynomial, state.polynomial):
        if polynomial.q != b.ORDER:
            raise ValueError('Memory polynomial field mismatch')
        polynomial.require_degree(srs.maximum_degree)
    if state.initial_polynomial(0) != points[0].y:
        raise ValueError('Initial polynomial genesis mismatch')
    if any(state.polynomial(p.x) != p.y for p in points):
        raise ValueError('Memory polynomial does not match macro-node points')
    if srs.commit(state.polynomial) != state.commitment:
        raise ValueError('Memory commitment mismatch')
    if b.multiply(b.generator(1), points[0].y, 1) != state.anchor:
        raise ValueError('Memory identity anchor mismatch')


def build(srs: SRS, y0: int, first: MacroPoint, second: MacroPoint) -> MemoryState:
    """MemBuild: MN0 plus the two already encoded audited interaction nodes."""
    points = _points((MacroPoint(0, scalar(y0)), first, second))
    if len(points) > srs.maximum_degree:
        raise ValueError('Macro-node count exceeds configured Nmax=dmax')
    polynomial = interpolate(b.ORDER, ((p.x, p.y) for p in points))
    state = MemoryState(points, polynomial, polynomial, srs.commit(polynomial),
                        b.multiply(b.generator(1), y0, 1), srs.identifier)
    validate(srs, state)
    return state


def create(srs: SRS, state: MemoryState, new_points, *, theta: int) -> MemoryState:
    """CREATE algebra with an externally supplied authorization point.

    No theta is retained, serialized or included in the returned state. The
    caller must derive it using the original H1(sUser||skPA||y0) specification.
    This primitive does not claim a complete authorization implementation.
    """
    validate(srs, state)
    theta = scalar(theta)
    added = _points(new_points)
    combined = _points(state.points + added)
    if len(combined) > srs.maximum_degree:
        raise ValueError('Macro-node count exceeds configured Nmax=dmax')
    tau = vanishing(b.ORDER, (theta,) + tuple(p.x for p in state.points))
    quotients = []
    for point in added:
        denominator = tau(point.x)
        if denominator == 0:
            raise ValueError('CREATE denominator is zero; no resampling rule is defined')
        quotients.append((point.x, (point.y - state.polynomial(point.x)) *
                          pow(denominator, -1, b.ORDER) % b.ORDER))
    delta = interpolate(b.ORDER, quotients)
    updated = state.polynomial + delta * tau
    updated.require_degree(srs.maximum_degree)
    if updated(theta) != state.initial_polynomial(theta):
        raise ValueError('CREATE authorization constraint failed')
    result = MemoryState(combined, state.initial_polynomial, updated,
                         srs.commit(updated), state.anchor, state.srs_id)
    validate(srs, result)
    return result


def append_polynomial_state(srs: SRS, state: MemoryState) -> MemoryState:
    """Only the paper's unchanged P/CP consequence, not event/CH APPEND itself."""
    validate(srs, state)
    return state


def synchronization_witness(srs: SRS, state: MemoryState) -> bytes:
    """InitSync W=h^phi(alpha), with actual G2 degree checking."""
    validate(srs, state)
    phi = vanishing(b.ORDER, (p.x for p in state.points))
    return srs.commit(phi, 2)
