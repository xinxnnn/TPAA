"""Explicit user-approved local experiments; never automatically selected."""
from .encoding import encode_value
from .merkle import Parameters


def keccak_typed_duplicate_last() -> Parameters:
    """Confirmed experiment, not paper-defined Merkle parameters."""
    from Crypto.Hash import keccak

    def digest(data: bytes) -> bytes:
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()

    return Parameters(digest, encode_value, 32, 'duplicate-last')
