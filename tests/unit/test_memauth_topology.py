import unittest
from dataclasses import replace

try:
    import py_ecc
    from Crypto.Hash import keccak
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import chameleon as ch
    from crypto.memauth.synthetic_macro import construct, append
    from crypto.memauth.topology_experiment import TopologyProof, verify


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class TopologyTests(unittest.TestCase):
    def test_append_topology_and_tamper_rejection(self):
        keys = ch.keygen()
        old = construct('macro:a', 't1', 'did:pa:test',
                        [('t1', 'read', 'doc', 'pa', 'tool')], keys.public, randomness=17)
        new = append(old, [('t2', 'write', 'doc', 'pa', 'tool')], keys.secret)
        proof = TopologyProof(new.digests, new.randomness)
        def check(value=proof, public=keys.public, key=old.digests[0]):
            return verify(public, old.point.x, old.ch_root, key, value)
        result = check()
        self.assertEqual(result.root, new.root)
        self.assertEqual(result.y, old.point.y)
        self.assertEqual(result.sequence_length, 2)
        for bad in (replace(proof, sequence=tuple(reversed(proof.sequence))),
                    replace(proof, sequence=proof.sequence[1:]),
                    replace(proof, randomness=(proof.randomness+1) % ch.backend.ORDER)):
            with self.assertRaises(ValueError):
                check(bad)
        with self.assertRaises(ValueError):
            check(public=ch.keygen().public)
        with self.assertRaises(ValueError):
            check(key=(old.digests[0]+1) % ch.backend.ORDER)


if __name__ == '__main__':
    unittest.main()
