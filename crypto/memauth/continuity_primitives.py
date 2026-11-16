"""PDF p8 open/upd equations only; NOT ContProve/ContVerify or a link fix.

SA keeps its supplied original snapshot. No successful proof advances that
snapshot. The unresolved link/topology transport prevents full authentication.
"""
from dataclasses import dataclass

from . import pairing_backend as b
from .kzg import open_at
from .memory import MemoryState, scalar, validate
from .polynomial import vanishing
from .srs import SRS


@dataclass(frozen=True)
class Proof:
    current_commitment: bytes
    opening: bytes
    update: bytes


def prove(srs: SRS, accepted: MemoryState, current: MemoryState, z: int, gamma: int) -> Proof:
    validate(srs, accepted)
    validate(srs, current)
    scalar(z)
    scalar(gamma)
    if gamma == 0:
        raise ValueError('Blinding factor must be in Fq*')
    if z not in {point.x for point in accepted.points}:
        raise ValueError('Challenge must refer to the supplied accepted snapshot')
    phi = vanishing(b.ORDER, (point.x for point in accepted.points))
    quotient = (current.polynomial - accepted.polynomial).exact_divide(phi)
    _, opening = open_at(srs, current.polynomial, z)
    return Proof(b.multiply(current.commitment, gamma, 1),
                 b.multiply(opening, gamma, 1),
                 b.multiply(srs.commit(quotient), gamma, 1))


def verify_equations(srs: SRS, accepted_commitment: bytes, witness: bytes,
                     k1: bytes, z: int, y: int, proof: Proof) -> dict[str, bool]:
    """Inputs are SA's already-blinded CP_old, G2 W and K1=g^gamma.

    y must be independently obtained from topology verification by caller.
    This routine does not verify topology, identity, signatures or link.
    """
    scalar(z)
    scalar(y)
    b.validate(k1, 1)
    if k1 == b.identity(1):
        raise ValueError('K1 must be nonidentity')
    difference = b.add(proof.current_commitment, b.multiply(accepted_commitment, -1, 1), 1)
    open_left = b.add(proof.current_commitment, b.multiply(k1, -y, 1), 1)
    challenge_g2 = b.add(srs.g2_powers[1], b.multiply(srs.g2_powers[0], -z, 2), 2)
    return {
        'updateEquation': b.pairing_equal(difference, srs.g2_powers[0], proof.update, witness),
        'openingEquation': b.pairing_equal(open_left, srs.g2_powers[0], proof.opening, challenge_g2),
    }
