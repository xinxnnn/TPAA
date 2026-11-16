"""Explicit synthetic profile: events -> macros -> build -> append -> create.

No credentials are issued; initialization sequences are labeled synthetic inputs,
not fabricated TP/AP audited transcripts. No private scalars are exported.
"""
import argparse
import json
from pathlib import Path

from crypto.memauth import chameleon as ch
from crypto.memauth import executable_profile as profile
from crypto.memauth.memory import build, create, append_polynomial_state, synchronization_witness
from crypto.memauth.srs import SRS
from crypto.memauth.synthetic_macro import construct, append


def run(srs):
    keys = ch.keygen()
    did = 'did:pa:synthetic-memory-demo'
    first = construct('macro:1', 't1', did, [('t1', 'read', 'doc', did, 'tool')],
                      keys.public, randomness=17)
    second = construct('macro:2', 't2', did, [('t2', 'ask', 'topic', did, 'chat')],
                       keys.public, randomness=19)
    # Explicit synthetic y0: not PHCFinalize, TP signature, or real identity binding.
    initial = build(srs, 13, first.point, second.point)
    appended = append(first, [('t3', 'write', 'doc', did, 'tool')], keys.secret)
    unchanged = append_polynomial_state(srs, initial)
    third = construct('macro:3', 't4', did, [('t4', 'plan', 'project', did, 'chat')],
                      keys.public, randomness=23)
    # User secret and derived point are local transient synthetic values only.
    import secrets
    synthetic_user_secret = secrets.token_bytes(32)
    theta = profile.h1(synthetic_user_secret, profile.scalar_bytes(keys.secret), profile.scalar_bytes(13))
    updated = create(srs, unchanged, (third.point,), theta=theta)
    witness = synchronization_witness(srs, updated)
    checks = {
        'appendMerkleChanged': appended.root != first.root,
        'appendChUnchanged': appended.ch_root == first.ch_root,
        'appendPointUnchanged': appended.point == first.point,
        'appendPolynomialCommitmentUnchanged': unchanged.commitment == initial.commitment,
        'createNewPointMatches': updated.polynomial(third.point.x) == third.point.y,
        'createOldPointsPreserved': all(updated.polynomial(p.x) == p.y for p in initial.points),
        'authorizationConstraint': updated.polynomial(theta) == initial.initial_polynomial(theta),
        'identityAnchorPreserved': updated.anchor == initial.anchor,
    }
    if not all(checks.values()):
        raise ValueError('Synthetic lifecycle checks failed')
    return {
        'scope': 'synthetic memory primitive lifecycle; not authenticated identity or Bootstrap',
        'profile': profile.manifest(),
        'initialSequences': 'synthetic event inputs; not audited TP/AP registration messages',
        'srsId': srs.identifier,
        'steps': [
            {'operation': 'MemBuild', 'degree': initial.polynomial.degree,
             'commitmentG1': initial.commitment.hex()},
            {'operation': 'APPEND', 'oldMerkleRoot': first.root.hex(),
             'newMerkleRoot': appended.root.hex(), 'unchangedChRoot': first.ch_root.hex()},
            {'operation': 'CREATE', 'degree': updated.polynomial.degree,
             'commitmentG1': updated.commitment.hex()},
            {'operation': 'InitSync witness only', 'witnessG2': witness.hex()},
        ],
        'checks': checks,
        'authentication': 'not-executed: original unresolved symbols remain diagnostic-only',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--srs', type=Path, required=True)
    args = parser.parse_args()
    with args.srs.open(encoding='utf-8') as stream:
        srs = SRS.from_artifact(json.load(stream))
    print(json.dumps(run(srs), indent=2))


if __name__ == '__main__':
    main()
