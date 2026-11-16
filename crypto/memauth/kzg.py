"""Unblinded KZG primitive (PDF section III.C); not the full MemAuth protocol."""
from . import pairing_backend as backend
from .polynomial import Polynomial
from .srs import SRS


def open_at(srs: SRS, polynomial: Polynomial, z: int) -> tuple[int, bytes]:
    # Validate original degree too: quotient fitting the SRS is insufficient.
    if polynomial.q != backend.ORDER:
        raise ValueError('Polynomial and SRS scalar fields differ')
    polynomial.require_degree(srs.maximum_degree)
    y = polynomial(z)
    quotient = (polynomial - Polynomial(polynomial.q, (y,))).exact_divide(
        Polynomial(polynomial.q, (-z, 1)))
    return y, srs.commit(quotient)


def verify(srs: SRS, commitment: bytes, z: int, y: int, proof: bytes) -> bool:
    """Invalid encodings raise ValueError; well-formed false claims return False."""
    if type(z) is not int or type(y) is not int:
        raise TypeError('Evaluation scalars must be integers')
    lhs = backend.add(commitment, backend.multiply(srs.g1_powers[0], -y, 1), 1)
    rhs_g2 = backend.add(srs.g2_powers[1], backend.multiply(srs.g2_powers[0], -z, 2), 2)
    return backend.pairing_equal(lhs, srs.g2_powers[0], proof, rhs_g2)
