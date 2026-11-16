"""Real AG2 conversation -> events -> MemAuth memory constraints.

Model API credentials are read only from environment. Synthetic tasks only.
"""
import argparse
import asyncio
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packages'))

from tpaa_runtime.memauth_agents import AgentBinding, config_from_env, interact
from crypto.memauth import executable_profile as p, chameleon as ch, pairing_backend as b
from crypto.memauth.synthetic_macro import construct, append
from crypto.memauth.memory import build, create, synchronization_witness
from crypto.memauth.continuity_primitives import prove, verify_equations
from crypto.memauth.topology_experiment import TopologyProof, verify as verify_topology
from crypto.memauth.srs import SRS


async def run(srs, task, *, config):
    pa = ch.keygen()
    # Synthetic local bindings, not falsely labeled as TP-issued credentials.
    did = 'did:pa:ag2-experiment'
    events, runtime = await interact(AgentBinding(did, 'synthetic-unissued'),
                                     AgentBinding('did:sa:ag2-summary', 'synthetic-unissued'), task, config=config)
    tuples = tuple((e.time, e.action, e.object, e.subject, e.method) for e in events)
    first = construct('initial:1', 'synthetic-init:1', did,
                      [('synthetic-init:1', 'initialize', 'synthetic-fixture', did, 'local')],
                      pa.public, randomness=secrets.randbelow(p.ORDER))
    second = construct('initial:2', 'synthetic-init:2', did,
                       [('synthetic-init:2', 'configure', 'synthetic-fixture', did, 'local')],
                       pa.public, randomness=secrets.randbelow(p.ORDER))
    old = build(srs, 13, first.point, second.point)
    appended = append(second, tuples[:1], pa.secret)
    new = construct('ag2:response', events[1].time, did, tuples[1:], pa.public,
                    randomness=secrets.randbelow(p.ORDER))
    theta = p.h1(secrets.token_bytes(32), p.scalar_bytes(pa.secret), p.scalar_bytes(13))
    current = create(srs, old, (new.point,), theta=theta)
    topology = verify_topology(pa.public, second.point.x, second.ch_root, second.digests[0],
                               TopologyProof(appended.digests, appended.randomness))
    gamma = 11  # Explicit public synthetic primitive vector, not a derived SA identity.
    proof = prove(srs, old, current, second.point.x, gamma)
    checks = verify_equations(srs, b.multiply(old.commitment, gamma, 1),
                              synchronization_witness(srs, old), b.multiply(b.generator(1), gamma, 1),
                              second.point.x, topology.y, proof)
    if not all(checks.values()):
        raise ValueError('AG2 memory proof checks failed')
    return {'scope': 'real AG2/model execution; synthetic unissued identity; memory primitive experiment',
            'profile': p.manifest(), 'srsId': srs.identifier, 'runtime': runtime,
            'events': [list(value) for value in tuples], 'checks': checks,
            'initialCommitment': old.commitment.hex(), 'currentCommitment': current.commitment.hex(),
            'fullAuthentication': 'not executed: unresolved paper symbols retained',
            'initialization': 'explicit synthetic fixtures; not TP/AP audit or issued credentials'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--srs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--task', default='Summarize why ordered memory commitments matter for research agents.')
    args = parser.parse_args()
    config = config_from_env()
    with args.srs.open(encoding='utf-8') as stream:
        srs = SRS.from_artifact(json.load(stream))
    trace = asyncio.run(run(srs, args.task, config=config))
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(trace, stream, ensure_ascii=False, indent=2)
