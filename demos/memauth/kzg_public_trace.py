"""Real KZG computation trace using explicitly public synthetic polynomial data.

Run as a module from the repository root. No PA credentials or secrets are read.
"""
import argparse
import json
from pathlib import Path
from time import perf_counter

from crypto.memauth import pairing_backend as b
from crypto.memauth.kzg import open_at, verify
from crypto.memauth.polynomial import Polynomial
from crypto.memauth.srs import SRS


def build_trace(srs):
    started = perf_counter()
    p = Polynomial(b.ORDER, (13, 5, 2))
    z = 3
    c = srs.commit(p)
    y, proof = open_at(srs, p, z)
    quotient = (p - Polynomial(b.ORDER, (y,))).exact_divide(Polynomial(b.ORDER, (-z, 1)))
    left_g1 = b.add(c, b.multiply(b.generator(1), -y, 1), 1)
    right_g2 = b.add(srs.g2_powers[1], b.multiply(b.generator(2), -z, 2), 2)
    accepts = verify(srs, c, z, y, proof)
    rejects_tampering = not verify(srs, c, z, y + 1, proof)
    return {
        'scope': 'public synthetic KZG primitive experiment; not MemAuth authentication',
        'source': 'memauth921.pdf section III.C',
        'backend': 'py-ecc==8.0.0 / BLS12-381',
        'srsId': srs.identifier,
        'scalarOrder': str(b.ORDER),
        'inputs': {'coefficientsAscending': [str(v) for v in p.coefficients], 'z': str(z)},
        'quotientCoefficientsAscending': [str(v) for v in quotient.coefficients],
        'formula': 'e(C-g*y,h) = e(proof,h_alpha-h*z)',
        'encoding': 'canonical compressed G1=48 bytes, G2=96 bytes; hex, big-endian',
        'outputs': {'commitmentG1': c.hex(), 'y': str(y), 'proofG1': proof.hex()},
        'pairingOperands': {
            'leftG1': left_g1.hex(), 'leftG2': srs.g2_powers[0].hex(),
            'rightG1': proof.hex(), 'rightG2': right_g2.hex(),
        },
        'verification': {'accepts': accepts, 'rejectsChangedY': rejects_tampering},
        'elapsedMs': (perf_counter() - started) * 1000,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--srs', required=True, type=Path)
    args = parser.parse_args()
    with args.srs.open(encoding='utf-8') as stream:
        srs = SRS.from_artifact(json.load(stream))
    print(json.dumps(build_trace(srs), indent=2))


if __name__ == '__main__':
    main()
