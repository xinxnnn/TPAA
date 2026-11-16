"""Phase 0 equations instantiated only in the approved local experiment profile.

No identity verification oracle or authenticated delivery is claimed. Each
role function accepts only the inputs it needs; orchestration is synthetic.
"""
from dataclasses import dataclass, field
from math import gcd
import secrets

from . import chameleon as ch, executable_profile as p, pairing_backend as b, ps


def encrypt(n: int, message: int) -> int:
    if type(n) is not int or n <= 2 or type(message) is not int or not 0 <= message < n:
        raise ValueError('Invalid Paillier modulus or plaintext')
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            return pow(n + 1, message, n*n) * pow(r, n, n*n) % (n*n)


def phc_init(n: int, identity_hash: int) -> int:
    """Identity verification is external; caller provides the experimental hash."""
    return encrypt(n, identity_hash)


def pa_construct(n: int, irf: int, ap_secret: int, ap_did: str, af: bytes) -> int:
    if type(irf) is not int or not 0 < irf < n*n or gcd(irf, n) != 1:
        raise ValueError('IRF must be a Paillier ciphertext unit')
    s_ap = p.prf(ap_secret, (ap_did, af), n)
    return irf * encrypt(n, s_ap) % (n*n)


@dataclass(frozen=True)
class Credential:
    y0: int = field(repr=False)
    delta_tp: bytes
    ktp: int = field(repr=False)
    did_pa: str


@dataclass(frozen=True)
class Registration:
    anchor: bytes
    did_pa: str
    rf: int = field(repr=False)
    af: bytes = field(repr=False)


@dataclass(frozen=True)
class Finalized:
    credential: Credential = field(repr=False)
    registration: Registration = field(repr=False)
    rho0: int = field(repr=False)
    h_root0: bytes


def finalize(n: int, issuer: ps.SecretKey, tp_did: str, domain: str,
             pa_public_key: bytes, cmc: tuple, rf: int, af: bytes) -> Finalized:
    b.validate(pa_public_key, 1)
    if pa_public_key == b.identity(1):
        raise ValueError('PA public key must be nonidentity')
    if type(rf) is not int or not 0 < rf < n*n or gcd(rf, n) != 1:
        raise ValueError('RF must be a Paillier ciphertext unit')
    if type(af) is not bytes or not af or type(cmc) is not tuple or not cmc:
        raise ValueError('Explicit AF bytes and ordered CMC tuple required')
    # Decimal field rendering is an explicitly local DID serialization.
    did = f'did:{domain}:{p.h1(af, rf)}'
    rho = secrets.randbelow(b.ORDER)
    root = ch.generate(pa_public_key, p.scalar_bytes(p.h1(cmc)), rho, h0=p.h0)
    y0 = p.h1(p.scalar_bytes(0), root, did)
    delta = ps.sign_phc_scalar(issuer, y0)
    # Global TP formula retained: PA DID is deliberately NOT an input.
    ktp = p.prf(issuer.x, (tp_did, p.scalar_bytes(issuer.y)), n)
    anchor = b.multiply(b.generator(1), y0, 1)
    return Finalized(Credential(y0, delta, ktp, did), Registration(anchor, did, rf, af), rho, root)


def recover_identity_hash(decrypted_rf: int, n: int, ap_secret: int, ap_did: str, af: bytes) -> int:
    """Joint unmasking equation only; authorized tracing policy is external."""
    return (decrypted_rf - p.prf(ap_secret, (ap_did, af), n)) % n
