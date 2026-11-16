"""Explicit global-PK injection experiment, not anonymous key delivery.

PDF topo supplies the full digest sequence and CH opening. Openings remain
transient and are intentionally excluded from default public trace exports.
"""
from dataclasses import dataclass, field

from . import pairing_backend as b, executable_profile as p, chameleon as ch
from .experiment_profiles import keccak_typed_duplicate_last
from .merkle import MerkleTree
from .memory import scalar


@dataclass(frozen=True)
class TopologyProof:
    sequence: tuple[int, ...] = field(repr=False)
    randomness: int = field(repr=False)


@dataclass(frozen=True)
class VerifiedTopology:
    root: bytes
    y: int = field(repr=False)
    sequence_length: int


def verify(public_key: bytes, z: int, expected_ch_root: bytes, historical_key: int,
           proof: TopologyProof) -> VerifiedTopology:
    """z, hRoot and Hkey must come from the verifier's accepted snapshot.

    Raises on rejection; never returns a usable y for an invalid topology.
    No signatures, link proof, identity or complete authentication are checked.
    """
    b.validate(public_key, 1)
    b.validate(expected_ch_root, 1)
    if public_key == b.identity(1):
        raise ValueError('Injected PA public key must be nonidentity')
    scalar(z)
    scalar(historical_key)
    scalar(proof.randomness)
    if type(proof.sequence) is not tuple or not proof.sequence:
        raise ValueError('Full nonempty digest sequence required')
    for digest in proof.sequence:
        scalar(digest)
    if historical_key not in proof.sequence:
        raise ValueError('Previously synchronized event digest is missing')
    root = MerkleTree(tuple(p.scalar_bytes(d) for d in proof.sequence),
                      parameters=keccak_typed_duplicate_last()).root
    if ch.generate(public_key, root, proof.randomness, h0=p.h0) != expected_ch_root:
        raise ValueError('Topology chameleon opening mismatch')
    return VerifiedTopology(root, p.h1(p.scalar_bytes(z), expected_ch_root), len(proof.sequence))
