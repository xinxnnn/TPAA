"""Offline, single-process research setup only; not a runtime setup endpoint.

Python cannot guarantee erasure of alpha from process memory. Run as a separate
short-lived process; no alpha is returned or serialized. This is not an MPC ceremony.
"""
import argparse
import json
import secrets
from pathlib import Path

from . import pairing_backend as backend
from .srs import SRS


def generate(maximum_degree: int) -> SRS:
    if type(maximum_degree) is not int or maximum_degree < 1:
        raise ValueError('Setup degree must be at least one')
    # Visually confirmed PDF p6 Setup: alpha is sampled from F_q^*.
    alpha = secrets.randbelow(backend.ORDER - 1) + 1
    exponent = 1
    g1, g2 = [], []
    for _ in range(maximum_degree + 1):
        g1.append(backend.multiply(backend.generator(1), exponent, 1))
        g2.append(backend.multiply(backend.generator(2), exponent, 2))
        exponent = exponent * alpha % backend.ORDER
    del alpha, exponent
    return SRS(tuple(g1), tuple(g2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--degree', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    srs = generate(args.degree)
    artifact = srs.to_artifact()
    # Exclusive creation prevents accidental replacement of an existing setup.
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(artifact, stream, indent=2)


if __name__ == '__main__':
    main()
