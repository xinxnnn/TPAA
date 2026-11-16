"""Explicitly approved synthetic execution profile; never a baseline default."""
import hashlib
import hmac

from .encoding import encode_value, hash_to_field
from .polynomial import BLS12_381_SCALAR_ORDER as ORDER

PROFILE_ID = 'memauth-synthetic-sha256-hmac-v1'


def scalar_bytes(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < ORDER:
        raise ValueError('Expected canonical Fq scalar')
    return value.to_bytes(32, 'big')


def h0(value) -> int:
    return hash_to_field(PROFILE_ID + '/H0', value, ORDER)


def h1(*parts) -> int:
    return hash_to_field(PROFILE_ID + '/H1', parts, ORDER)


def h2(event) -> int:
    return hash_to_field(PROFILE_ID + '/H2', event, ORDER)


def _sample(key: bytes, domain: str, parts, modulus: int, *, nonzero=False) -> int:
    if type(key) is not bytes or not key:
        raise ValueError('Nonempty byte key required')
    if type(modulus) is not int or modulus < 2 or modulus.bit_length() > 16384:
        raise ValueError('Unsupported experimental modulus')
    width = (modulus.bit_length() + 7) // 8
    excess = width * 8 - modulus.bit_length()
    blocks = (width + 31) // 32
    for attempt in range(2**32):
        output = b''.join(hmac.new(key, encode_value((PROFILE_ID, domain, parts, attempt, block)),
                                   hashlib.sha256).digest() for block in range(blocks))
        candidate = int.from_bytes(output[:width], 'big') >> excess
        if candidate < modulus and (candidate != 0 or not nonzero):
            return candidate
    raise RuntimeError('Experimental derivation rejection limit exceeded')


def kdf(secret: int, service_did: str) -> int:
    return _sample(scalar_bytes(secret), 'KDF', (service_did,), ORDER, nonzero=True)


def prf(key: int, parts: tuple, modulus: int) -> int:
    return _sample(scalar_bytes(key), 'PRF', parts, modulus)


def manifest():
    return {
        'profileId': PROFILE_ID, 'scope': 'explicit synthetic experiment only',
        'scalarEncoding': '32-byte big-endian canonical Fq',
        'groupEncoding': 'canonical compressed BLS12-381 G1/G2',
        'structuredEncoding': 'MA1 typed length-prefix encoding',
        'hashes': 'domain-separated SHA-256 rejection sampling to Fq',
        'KDF': 'domain-separated HMAC-SHA-256 counter expansion/rejection to Fq*',
        'PRF': 'domain-separated HMAC-SHA-256 counter expansion/rejection to Zn',
        'baselineDefault': False,
    }
