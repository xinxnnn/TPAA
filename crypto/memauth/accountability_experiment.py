"""PDF Phase 4 role-separated algebra in the approved experiment profile.

Authorization, evidence validation and secure TP/AP transport are external.
No PII or identity hash is included in default public results.
"""
from dataclasses import dataclass, field

from . import pairing_backend as b, executable_profile as p, ps
from .issuance_experiment import Registration


def unblind(issuer: ps.SecretKey, tp_did: str, sa_did: str, modulus: int,
            blinded_anchor: bytes) -> bytes:
    ktp = p.prf(issuer.x, (tp_did, p.scalar_bytes(issuer.y)), modulus)
    gamma = p.h1(ktp, sa_did)
    if gamma == 0:
        raise ValueError('Noninvertible blinding factor; no resampling rule defined')
    return b.multiply(blinded_anchor, pow(gamma, -1, b.ORDER), 1)


def locate(anchor: bytes, registrations: tuple[Registration, ...]) -> Registration | None:
    b.validate(anchor, 1)
    matches = [record for record in registrations if record.anchor == anchor]
    if len(matches) > 1:
        raise ValueError('Ambiguous registration index; no tie rule defined')
    return matches[0] if matches else None


def ap_share(ap_secret: int, ap_did: str, af: bytes, modulus: int) -> int:
    """AP returns sAP only after external tracing approval; no RF/private TP key."""
    return p.prf(ap_secret, (ap_did, af), modulus)


@dataclass(frozen=True)
class Link:
    anchor: bytes
    did_pa: str
    identity_hash: int = field(repr=False)


def finish(record: Registration, decrypted_rf: int, s_ap: int, modulus: int,
           known_identity_hashes: frozenset[int]) -> Link | None:
    """TP removes AP mask and checks its supplied registration ledger."""
    if type(modulus) is not int or modulus < 2:
        raise ValueError('Invalid Paillier modulus')
    for value in (decrypted_rf, s_ap):
        if type(value) is not int or not 0 <= value < modulus:
            raise ValueError('Expected canonical Zn value')
    recovered = (decrypted_rf - s_ap) % modulus
    if recovered not in known_identity_hashes:
        return None
    return Link(record.anchor, record.did_pa, recovered)
