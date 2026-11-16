"""Synthetic operation-output audit -> Seq1/Seq2 -> real memory commitment.

This exercise is not full PHC issuance: RF is a clearly labeled synthetic
ciphertext fixture, while delta_TP is computed by the actual signature primitive.
"""
import argparse
import json
import secrets
from pathlib import Path

from crypto.memauth import chameleon as ch, ps
from crypto.memauth.audit_events import APConstructPublic, TPFinalizePublic, observe, initial_memory
from crypto.memauth.srs import SRS


def run(srs):
    pa = ch.keygen()
    issuer = ps.SecretKey(secrets.randbelow(ch.backend.ORDER - 1) + 1,
                          secrets.randbelow(ch.backend.ORDER - 1) + 1)
    y0 = 13  # Explicit synthetic input, not a claimed PHCFinalize-derived identity.
    delta = ps.sign_phc_scalar(issuer, y0)
    tp = observe('synthetic-step:2', 'did:tp:synthetic', TPFinalizePublic(pa.public, delta))
    ap = observe('synthetic-step:1', 'did:ap:synthetic', APConstructPublic(1234567))
    state, first, second = initial_memory(
        srs, y0, 'did:pa:synthetic', pa.public, tp, ap,
        tp_rho=secrets.randbelow(ch.backend.ORDER), ap_rho=secrets.randbelow(ch.backend.ORDER))
    return {
        'scope': 'synthetic audit adapter exercise; not full credential issuance or authentication',
        'inputOrigins': {'deltaTP': 'actual PS fixed-base operation result',
                         'RF': 'synthetic ciphertext fixture; no Paillier issuance claimed',
                         'y0': 'synthetic scalar fixture'},
        'TP': tp.public_trace(), 'AP': ap.public_trace(),
        'commitmentG1': state.commitment.hex(), 'degree': state.polynomial.degree,
        'checks': {'signatureEquation': ps.verify_phc_scalar(issuer.public_key(), y0, delta),
                   'Seq1EqualsTPH2': first.digests == (tp.event_digest,),
                   'Seq2EqualsAPH2': second.digests == (ap.event_digest,),
                   'genesisPreserved': state.polynomial(0) == y0},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--srs', type=Path, required=True)
    args = parser.parse_args()
    with args.srs.open(encoding='utf-8') as stream:
        srs = SRS.from_artifact(json.load(stream))
    print(json.dumps(run(srs), indent=2))
