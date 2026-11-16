"""PDF section III.B PS signatures and the distinct PHC fixed-base equation.

These are algebraic primitives, not PHC issuance or InitProve. No hashes,
protocol encoding, PA registration, or disputed link-proof symbols are supplied.
"""
from dataclasses import dataclass, field
import secrets

from . import pairing_backend as b


def _scalar(value: int, *, nonzero: bool = False) -> int:
    if type(value) is not int or not 0 <= value < b.ORDER or (nonzero and value == 0):
        raise ValueError('Expected a canonical scalar' + (' in Fq*' if nonzero else ' in Fq'))
    return value


def _random_nonzero() -> int:
    return secrets.randbelow(b.ORDER - 1) + 1


@dataclass(frozen=True)
class SecretKey:
    x: int = field(repr=False)
    y: int = field(repr=False)

    def __post_init__(self):
        _scalar(self.x)
        _scalar(self.y)

    def public_key(self):
        return PublicKey(b.multiply(b.generator(2), self.x, 2),
                         b.multiply(b.generator(2), self.y, 2))


@dataclass(frozen=True)
class PublicKey:
    x: bytes
    y: bytes

    def __post_init__(self):
        b.validate(self.x, 2)
        b.validate(self.y, 2)


@dataclass(frozen=True)
class Signature:
    first: bytes
    second: bytes


def keygen() -> SecretKey:
    """III.B explicitly samples x,y from Fq, including zero."""
    return SecretKey(secrets.randbelow(b.ORDER), secrets.randbelow(b.ORDER))


def sign(key: SecretKey, message: int, *, randomizer: int | None = None) -> Signature:
    """Explicit randomizer supports public synthetic vectors; otherwise use CSPRNG."""
    message = _scalar(message)
    u = _random_nonzero() if randomizer is None else _scalar(randomizer, nonzero=True)
    first = b.multiply(b.generator(1), u, 1)
    return Signature(first, b.multiply(first, (key.x + key.y * message) % b.ORDER, 1))


def verify(key: PublicKey, message: int, signature: Signature) -> bool:
    message = _scalar(message)
    b.validate(signature.first, 1)
    b.validate(signature.second, 1)
    if signature.first == b.identity(1):
        return False  # Explicit III.B verification condition.
    right_g2 = b.add(key.x, b.multiply(key.y, message, 2), 2)
    return b.pairing_equal(signature.first, right_g2, signature.second, b.generator(2))


def rerandomize(signature: Signature, *, randomizer: int | None = None) -> Signature:
    b.validate(signature.first, 1)
    b.validate(signature.second, 1)
    if signature.first == b.identity(1):
        raise ValueError('PS first component must not be the identity')
    r = _random_nonzero() if randomizer is None else _scalar(randomizer, nonzero=True)
    return Signature(b.multiply(signature.first, r, 1), b.multiply(signature.second, r, 1))


def sign_phc_scalar(key: SecretKey, y0: int) -> bytes:
    """Phase 0 delta_TP=g^(c1+c2*y0), NOT a full III.B signature tuple.

    Phase 0 samples c1,c2 from Fq*, unlike general PS keygen.
    """
    _scalar(key.x, nonzero=True)
    _scalar(key.y, nonzero=True)
    y0 = _scalar(y0)
    return b.multiply(b.generator(1), (key.x + key.y * y0) % b.ORDER, 1)


def verify_phc_scalar(key: PublicKey, y0: int, delta: bytes) -> bool:
    """Only the credential pairing equation; no identity issuance claims."""
    y0 = _scalar(y0)
    b.validate(delta, 1)
    rhs = b.add(key.x, b.multiply(key.y, y0, 2), 2)
    return b.pairing_equal(delta, b.generator(2), b.generator(1), rhs)
