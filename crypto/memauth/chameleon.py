"""PDF p4 chameleon hash over BLS12-381 G1."""
from dataclasses import dataclass, field
import secrets

from . import pairing_backend as backend
from typing import Callable


@dataclass(frozen=True)
class KeyPair:
    secret: int = field(repr=False)
    public: bytes


def keygen() -> KeyPair:
    # PDF samples Z_p^* because CH adaptation requires sk^{-1}.
    secret = 0
    while secret == 0:
        secret = secrets.randbelow(backend.ORDER)
    return KeyPair(secret, backend.multiply(backend.generator(1), secret, 1))


def message_scalar(message, h0: Callable[[object], int]) -> int:
    value = h0(message)
    if type(value) is not int or not 0 <= value < backend.ORDER:
        raise ValueError('H0 must return a canonical BLS12-381 scalar')
    return value


def generate(public_key: bytes, message, randomness: int, *, h0: Callable[[object], int]) -> bytes:
    backend.validate(public_key, 1)
    if type(randomness) is not int:
        raise TypeError('Randomness must be an integer')
    left = backend.multiply(backend.generator(1), message_scalar(message, h0), 1)
    right = backend.multiply(public_key, randomness, 1)
    return backend.add(left, right, 1)


def adapt(secret_key: int, old_message, old_randomness: int, new_message, *, h0: Callable[[object], int]) -> int:
    q = backend.ORDER
    if type(secret_key) is not int or secret_key % q == 0:
        raise ValueError('Chameleon secret key must be nonzero')
    if type(old_randomness) is not int:
        raise TypeError('Randomness must be an integer')
    delta = (message_scalar(old_message, h0) - message_scalar(new_message, h0)) % q
    return (old_randomness + delta * pow(secret_key, -1, q)) % q


def verify_collision(public_key: bytes, old_message, old_randomness: int, new_message, new_randomness: int,
                     *, h0: Callable[[object], int]) -> bool:
    try:
        return generate(public_key, old_message, old_randomness, h0=h0) == generate(
            public_key, new_message, new_randomness, h0=h0)
    except (TypeError, ValueError):
        return False
