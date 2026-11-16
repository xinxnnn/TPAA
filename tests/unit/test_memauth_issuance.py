import unittest
from math import lcm

try:
    import py_ecc
except ModuleNotFoundError:
    py_ecc = None

if py_ecc is not None:
    from crypto.memauth import issuance_experiment as issue, chameleon as ch, ps


@unittest.skipIf(py_ecc is None, 'Requires optional memauth dependencies')
class IssuanceTests(unittest.TestCase):
    def test_joint_recovery_and_global_ktp(self):
        # Explicit tiny synthetic Paillier fixture; never a deployment key.
        n = 101 * 113
        lam = lcm(100, 112)
        irf = issue.phc_init(n, 73)
        rf = issue.pa_construct(n, irf, 17, 'did:ap:test', b'af')
        masked = ((pow(rf, lam, n*n)-1)//n * pow(lam, -1, n)) % n
        self.assertEqual(issue.recover_identity_hash(masked, n, 17, 'did:ap:test', b'af'), 73)
        pa = ch.keygen()
        issuer = ps.SecretKey(3, 5)
        first = issue.finalize(n, issuer, 'did:tp:test', 'test', pa.public, ('module:1',), rf, b'af')
        other = issue.finalize(n, issuer, 'did:tp:test', 'test', ch.keygen().public,
                               ('module:2',), rf, b'other-af')
        self.assertTrue(ps.verify_phc_scalar(issuer.public_key(), first.credential.y0,
                                             first.credential.delta_tp))
        self.assertEqual(first.credential.ktp, other.credential.ktp)
        self.assertNotEqual(first.credential.did_pa, other.credential.did_pa)
        with self.assertRaises(ValueError):
            issue.pa_construct(n, n, 17, 'did:ap:test', b'af')


if __name__ == '__main__':
    unittest.main()
